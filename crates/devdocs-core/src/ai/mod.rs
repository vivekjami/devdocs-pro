//! AI integration modules for DevDocs Pro

pub mod batch_processor;
pub mod gemini_client;
pub mod prompts;

pub use batch_processor::AIBatchProcessor;
pub use gemini_client::{GeminiClient, GeminiPrompt, GeminiResponse, PromptType};
