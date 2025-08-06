//! AI integration modules for DevDocs Pro

pub mod gemini_client;
pub mod prompts;
pub mod batch_processor;

pub use gemini_client::{GeminiClient, GeminiPrompt, GeminiResponse, PromptType};
pub use batch_processor::AIBatchProcessor;
