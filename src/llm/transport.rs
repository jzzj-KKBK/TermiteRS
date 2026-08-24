//! LLM HTTP 传输层。
//!
//! 统一处理端点、鉴权、重试和流式响应，不包含业务提示词与安全判定。

use std::{env, io::Read, thread, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use reqwest::blocking::Client;
use serde::Serialize;
use serde_json::Value;
use tracing::warn;

use crate::config::{LlmConfig, LlmProvider};

#[derive(Debug, Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    temperature: f32,
    stream: bool,
    messages: Vec<ChatMessage<'a>>,
}

#[derive(Debug, Serialize)]
struct ChatMessage<'a> {
    role: &'a str,
    content: &'a str,
}

fn chat_completions_endpoint(config: &LlmConfig) -> Result<String> {
    let base = match (&config.base_url, config.provider) {
        (Some(base_url), _) => base_url.clone(),
        (None, LlmProvider::DeepSeek) => "https://api.deepseek.com".to_string(),
        (None, LlmProvider::OpenAi) => "https://api.openai.com/v1".to_string(),
        (None, LlmProvider::OpenAiCompatible | LlmProvider::Custom) => {
            bail!("base_url is required for provider {:?}", config.provider)
        }
    };

    let base = base.trim_end_matches('/');
    if base.ends_with("/chat/completions") {
        Ok(base.to_string())
    } else {
        Ok(format!("{base}/chat/completions"))
    }
}

pub(super) fn call_chat(
    config: &LlmConfig,
    system_prompt: &str,
    user_prompt: &str,
) -> Result<String> {
    let attempts = config.max_retries.saturating_add(1);
    for attempt in 1..=attempts {
        match call_chat_once(config, system_prompt, user_prompt) {
            Ok(content) => return Ok(content),
            Err(err) if attempt < attempts && is_retryable_llm_error(&err) => {
                warn!("LLM request attempt {attempt}/{attempts} failed, retrying: {err:#}");
                thread::sleep(Duration::from_secs(u64::from(attempt.min(5))));
            }
            Err(err) => return Err(err),
        }
    }
    bail!("LLM request did not run")
}

fn call_chat_once(config: &LlmConfig, system_prompt: &str, user_prompt: &str) -> Result<String> {
    let api_key = env::var(&config.api_key_env)
        .with_context(|| format!("missing LLM API key env {}", config.api_key_env))?;
    let endpoint = chat_completions_endpoint(config)?;

    let body = ChatRequest {
        model: &config.model,
        temperature: config.temperature,
        stream: false,
        messages: vec![
            ChatMessage {
                role: "system",
                content: system_prompt,
            },
            ChatMessage {
                role: "user",
                content: user_prompt,
            },
        ],
    };

    let client = llm_client(config)?;
    let response: Value = client
        .post(endpoint)
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .context("failed to call LLM provider")?
        .error_for_status()
        .context("LLM provider returned an error status")?
        .json()
        .context("failed to parse LLM response")?;

    let content = response["choices"][0]["message"]["content"]
        .as_str()
        .ok_or_else(|| anyhow!("LLM response did not contain choices[0].message.content"))?;

    Ok(content.trim().to_string())
}

fn llm_client(config: &LlmConfig) -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(config.timeout_seconds.max(1)))
        .build()
        .context("failed to build LLM HTTP client")
}

fn is_retryable_llm_error(err: &anyhow::Error) -> bool {
    let message = err
        .chain()
        .map(|cause| cause.to_string().to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" | ");
    message.contains("timed out")
        || message.contains("timeout")
        || message.contains("connection")
        || message.contains("server error")
        || message.contains("body")
}

pub(super) fn call_chat_streaming<F>(
    config: &LlmConfig,
    system_prompt: &str,
    user_prompt: &str,
    on_delta: &mut F,
) -> Result<String>
where
    F: FnMut(&str) -> Result<()>,
{
    let api_key = env::var(&config.api_key_env)
        .with_context(|| format!("missing LLM API key env {}", config.api_key_env))?;
    let endpoint = chat_completions_endpoint(config)?;

    let body = ChatRequest {
        model: &config.model,
        temperature: config.temperature,
        stream: true,
        messages: vec![
            ChatMessage {
                role: "system",
                content: system_prompt,
            },
            ChatMessage {
                role: "user",
                content: user_prompt,
            },
        ],
    };

    let mut response = llm_client(config)?
        .post(endpoint)
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .context("failed to call LLM provider")?
        .error_for_status()
        .context("LLM provider returned an error status")?;

    let mut buffer = [0_u8; 8192];
    let mut pending = Vec::new();
    let mut content = String::new();

    loop {
        let read = response
            .read(&mut buffer)
            .context("failed to read LLM stream")?;
        if read == 0 {
            break;
        }

        pending.extend_from_slice(&buffer[..read]);
        while let Some(index) = pending.iter().position(|byte| *byte == b'\n') {
            let line = pending.drain(..=index).collect::<Vec<_>>();
            let line = String::from_utf8_lossy(&line);
            let line = line.trim();
            if line.is_empty() || !line.starts_with("data:") {
                continue;
            }

            let data = line.trim_start_matches("data:").trim();
            if data == "[DONE]" {
                return Ok(content.trim().to_string());
            }

            let value: Value = serde_json::from_str(data).context("failed to parse LLM stream")?;
            if let Some(delta) = value["choices"][0]["delta"]["content"].as_str() {
                content.push_str(delta);
                on_delta(delta)?;
            }
        }
    }

    Ok(content.trim().to_string())
}
