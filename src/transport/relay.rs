use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use futures_util::{Sink, SinkExt, Stream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_tungstenite::tungstenite::Message;

use crate::transport::{TransportError, WsStream};

const DATA_FRAME: u8 = 0;
const FIN_FRAME: u8 = 1;
const RESET_FRAME: u8 = 2;
const MAX_RESET_REASON: usize = 1024;
const RELAY_DATA_CHUNK: usize = 16 * 1024;

pub struct RelayByteStream {
    websocket: WsStream,
    pending_read: Bytes,
    read_finished: bool,
    write_finished: bool,
    terminal_error: Option<(io::ErrorKind, String)>,
    close_flushed: bool,
    transport_shutdown: bool,
}

impl RelayByteStream {
    pub fn from_ws(websocket: WsStream) -> Self {
        Self {
            websocket,
            pending_read: Bytes::new(),
            read_finished: false,
            write_finished: false,
            terminal_error: None,
            close_flushed: false,
            transport_shutdown: false,
        }
    }

    pub async fn reset(&mut self, reason: &[u8]) -> Result<(), TransportError> {
        if reason.len() > MAX_RESET_REASON {
            return Err(TransportError::Configuration(
                "relay RESET reason exceeds 1024 bytes".to_owned(),
            ));
        }
        let mut payload = Vec::with_capacity(reason.len() + 1);
        payload.push(RESET_FRAME);
        payload.extend_from_slice(reason);
        self.websocket
            .send(Message::Binary(Bytes::from(payload)))
            .await
            .map_err(|error| TransportError::WebSocket(format!("send relay RESET: {error}")))?;
        self.websocket
            .send(Message::Close(None))
            .await
            .map_err(|error| {
                TransportError::WebSocket(format!("close reset relay stream: {error}"))
            })?;
        self.websocket
            .get_mut()
            .shutdown()
            .await
            .map_err(TransportError::Network)?;
        self.read_finished = true;
        self.write_finished = true;
        self.close_flushed = true;
        self.transport_shutdown = true;
        self.terminal_error = Some((
            io::ErrorKind::ConnectionReset,
            String::from_utf8_lossy(reason).into_owned(),
        ));
        Ok(())
    }

    fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.close_flushed {
            match Pin::new(&mut self.websocket).poll_close(cx) {
                Poll::Ready(Ok(())) => self.close_flushed = true,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
                Poll::Pending => return Poll::Pending,
            }
        }
        if !self.transport_shutdown {
            match Pin::new(self.websocket.get_mut()).poll_shutdown(cx) {
                Poll::Ready(Ok(())) => {
                    self.transport_shutdown = true;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn set_terminal_error(&mut self, kind: io::ErrorKind, message: impl Into<String>) {
        self.terminal_error = Some((kind, message.into()));
        self.read_finished = true;
        self.write_finished = true;
    }
}

impl AsyncRead for RelayByteStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some((kind, message)) = &self.terminal_error {
            return Poll::Ready(Err(io::Error::new(*kind, message.clone())));
        }
        if self.read_finished {
            return if self.write_finished {
                self.poll_close(cx)
            } else {
                Poll::Ready(Ok(()))
            };
        }
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if !self.pending_read.is_empty() {
            let length = self.pending_read.len().min(buffer.remaining());
            let bytes = self.pending_read.split_to(length);
            buffer.put_slice(&bytes);
            return Poll::Ready(Ok(()));
        }

        loop {
            match Pin::new(&mut self.websocket).poll_next(cx) {
                Poll::Ready(Some(Ok(Message::Binary(mut payload)))) => {
                    if payload.is_empty() {
                        self.set_terminal_error(
                            io::ErrorKind::InvalidData,
                            "relay binary frame has no type byte",
                        );
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "relay binary frame has no type byte",
                        )));
                    }
                    let frame = payload[0];
                    payload.advance(1);
                    match frame {
                        DATA_FRAME => {
                            if payload.is_empty() {
                                continue;
                            }
                            let bytes = payload.split_to(payload.len().min(buffer.remaining()));
                            buffer.put_slice(&bytes);
                            self.pending_read = payload;
                            return Poll::Ready(Ok(()));
                        }
                        FIN_FRAME if payload.is_empty() => {
                            self.read_finished = true;
                            if self.write_finished {
                                return self.poll_close(cx);
                            }
                            return Poll::Ready(Ok(()));
                        }
                        RESET_FRAME if payload.len() <= MAX_RESET_REASON => {
                            let message = String::from_utf8_lossy(&payload).into_owned();
                            self.set_terminal_error(
                                io::ErrorKind::ConnectionReset,
                                message.clone(),
                            );
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::ConnectionReset,
                                message,
                            )));
                        }
                        FIN_FRAME => {
                            self.set_terminal_error(
                                io::ErrorKind::InvalidData,
                                "relay FIN frame must contain only its type byte",
                            );
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "relay FIN frame must contain only its type byte",
                            )));
                        }
                        RESET_FRAME => {
                            self.set_terminal_error(
                                io::ErrorKind::InvalidData,
                                "relay RESET reason exceeds 1024 bytes",
                            );
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "relay RESET reason exceeds 1024 bytes",
                            )));
                        }
                        _ => {
                            self.set_terminal_error(
                                io::ErrorKind::InvalidData,
                                format!("unknown relay frame type {frame}"),
                            );
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("unknown relay frame type {frame}"),
                            )));
                        }
                    }
                }
                Poll::Ready(Some(Ok(Message::Close(_)))) => {
                    if self.read_finished && self.write_finished {
                        return self.poll_close(cx);
                    }
                    self.set_terminal_error(
                        io::ErrorKind::ConnectionReset,
                        "relay WebSocket closed before both half-close frames",
                    );
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "relay WebSocket closed before both half-close frames",
                    )));
                }
                Poll::Ready(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {
                    match Pin::new(&mut self.websocket).poll_flush(cx) {
                        Poll::Ready(Ok(())) => continue,
                        Poll::Ready(Err(error)) => {
                            return Poll::Ready(Err(io::Error::other(error)));
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
                Poll::Ready(Some(Ok(Message::Text(_)))) => {
                    self.set_terminal_error(
                        io::ErrorKind::InvalidData,
                        "relay transport accepts binary frames only",
                    );
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "relay transport accepts binary frames only",
                    )));
                }
                Poll::Ready(Some(Ok(Message::Frame(_)))) => {
                    self.set_terminal_error(
                        io::ErrorKind::InvalidData,
                        "raw WebSocket frame escaped the message decoder",
                    );
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "raw WebSocket frame escaped the message decoder",
                    )));
                }
                Poll::Ready(Some(Err(error))) => {
                    self.set_terminal_error(io::ErrorKind::ConnectionReset, error.to_string());
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, error)));
                }
                Poll::Ready(None) => {
                    self.set_terminal_error(
                        io::ErrorKind::ConnectionReset,
                        "relay WebSocket ended without a close frame",
                    );
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "relay WebSocket ended without a close frame",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for RelayByteStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_finished {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "relay write direction is finished",
            )));
        }
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match Pin::new(&mut self.websocket).poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                let written = buffer.len().min(RELAY_DATA_CHUNK);
                let mut frame = Vec::with_capacity(written + 1);
                frame.push(DATA_FRAME);
                frame.extend_from_slice(&buffer[..written]);
                match Pin::new(&mut self.websocket).start_send(Message::Binary(Bytes::from(frame)))
                {
                    Ok(()) => Poll::Ready(Ok(written)),
                    Err(error) => Poll::Ready(Err(io::Error::other(error))),
                }
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(io::Error::other(error))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.websocket)
            .poll_flush(cx)
            .map_err(io::Error::other)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.write_finished {
            match Pin::new(&mut self.websocket).poll_ready(cx) {
                Poll::Ready(Ok(())) => {
                    if let Err(error) = Pin::new(&mut self.websocket)
                        .start_send(Message::Binary(Bytes::from_static(&[FIN_FRAME])))
                    {
                        return Poll::Ready(Err(io::Error::other(error)));
                    }
                    self.write_finished = true;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
                Poll::Pending => return Poll::Pending,
            }
        }
        match Pin::new(&mut self.websocket).poll_flush(cx) {
            Poll::Ready(Ok(())) if self.read_finished => self.poll_close(cx),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(io::Error::other(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}
