use std::io::{Read, Write};

use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;

pub const DEFAULT_MAX_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("I/O error while processing IPC frame: {0}")]
    Io(#[from] std::io::Error),
    #[error("IPC frame is {actual} bytes; maximum is {maximum}")]
    TooLarge { actual: usize, maximum: usize },
    #[error("invalid JSON IPC payload: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn write_json_frame<W: Write, T: Serialize>(
    writer: &mut W,
    value: &T,
    max_bytes: usize,
) -> Result<(), FrameError> {
    let payload = serde_json::to_vec(value)?;
    if payload.len() > max_bytes {
        return Err(FrameError::TooLarge {
            actual: payload.len(),
            maximum: max_bytes,
        });
    }

    let length = u32::try_from(payload.len()).map_err(|_| FrameError::TooLarge {
        actual: payload.len(),
        maximum: u32::MAX as usize,
    })?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

pub fn read_json_frame<R: Read, T: DeserializeOwned>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<T, FrameError> {
    let mut header = [0_u8; 4];
    reader.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length > max_bytes {
        return Err(FrameError::TooLarge {
            actual: length,
            maximum: max_bytes,
        });
    }

    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload)?;
    Ok(serde_json::from_slice(&payload)?)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Message {
        value: String,
    }

    #[test]
    fn framed_json_round_trips() {
        let expected = Message {
            value: "hello".to_string(),
        };
        let mut bytes = Vec::new();
        write_json_frame(&mut bytes, &expected, 128).expect("write frame");
        let actual: Message = read_json_frame(&mut Cursor::new(bytes), 128).expect("read frame");
        assert_eq!(actual, expected);
    }

    #[test]
    fn oversized_write_is_rejected() {
        let message = Message {
            value: "x".repeat(100),
        };
        let error = write_json_frame(&mut Vec::new(), &message, 16)
            .expect_err("oversized payload should fail");
        assert!(matches!(error, FrameError::TooLarge { .. }));
    }

    #[test]
    fn oversized_read_is_rejected_before_allocation() {
        let bytes = (4096_u32).to_be_bytes();
        let error = read_json_frame::<_, Message>(&mut Cursor::new(bytes), 64)
            .expect_err("oversized length should fail");
        assert!(matches!(error, FrameError::TooLarge { .. }));
    }
}
