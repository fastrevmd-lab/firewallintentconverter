/**
 * ReviewChatPanel Component
 *
 * Full-ruleset LLM chat review panel. Appears in the right panel when all rules
 * are accepted and user clicks "Review". Supports multi-turn conversation with
 * inline suggestion parsing and accept/reject per suggestion.
 */
import React, { useState, useEffect, useRef } from 'react';
import { safeJsonParse } from '../utils/safe-json.js';
import {
  getLLMChatResponse,
  getLLMStatus,
  loadSystemPrompt,
  buildFullReviewPrompt,
} from '../utils/llm-client.js';

export default function ReviewChatPanel({
  intermediateConfig,
  onUpdateRule,
  targetModel,
  isSanitized,
  llmWarningDismissed,
  onLLMWarning,
  onExitReview,
  srxLicense,
}) {
  const [messages, setMessages] = useState([]);
  const [inputText, setInputText] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const messagesEndRef = useRef(null);
  const hasInitialized = useRef(false);

  const llmStatus = getLLMStatus();

  // Auto-scroll to bottom when messages change
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Auto-send initial review prompt on mount
  useEffect(() => {
    if (hasInitialized.current) return;
    hasInitialized.current = true;

    if (!llmStatus.configured) {
      setError('No LLM provider configured. Open Settings to configure one.');
      return;
    }

    if (!isSanitized && !llmWarningDismissed) {
      if (onLLMWarning) onLLMWarning();
      return;
    }

    sendInitialReview();
  }, []);

  /** Send the initial full-ruleset review prompt */
  const sendInitialReview = async () => {
    const prompt = buildFullReviewPrompt(intermediateConfig, targetModel, srxLicense);
    const userMsg = { role: 'user', content: prompt.user };

    setMessages([userMsg]);
    setIsLoading(true);
    setError('');

    try {
      const response = await getLLMChatResponse([userMsg], prompt.system);
      const assistantMsg = { role: 'assistant', content: response };
      setMessages(prev => [...prev, assistantMsg]);
    } catch (err) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  /** Send a follow-up message */
  const handleSend = async () => {
    const text = inputText.trim();
    if (!text || isLoading) return;

    const userMsg = { role: 'user', content: text };
    const updatedMessages = [...messages, userMsg];
    setMessages(updatedMessages);
    setInputText('');
    setIsLoading(true);
    setError('');

    try {
      const systemPrompt = loadSystemPrompt('fullReview');
      const response = await getLLMChatResponse(updatedMessages, systemPrompt);
      const assistantMsg = { role: 'assistant', content: response };
      setMessages(prev => [...prev, assistantMsg]);
    } catch (err) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  /** Handle Enter to send */
  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  /** Parse inline JSON suggestion blocks from a message */
  const parseMessageContent = (content) => {
    const parts = [];
    // Split on ```json ... ``` blocks
    const regex = /```json\s*\n?([\s\S]*?)\n?\s*```/g;
    let lastIndex = 0;
    let match;

    while ((match = regex.exec(content)) !== null) {
      // Text before this block
      if (match.index > lastIndex) {
        parts.push({ type: 'text', content: content.slice(lastIndex, match.index) });
      }
      // Try to parse the JSON
      try {
        const json = safeJsonParse(match[1].trim());
        if (json.rule_name && json.field) {
          parts.push({ type: 'suggestion', data: json });
        } else {
          parts.push({ type: 'text', content: match[0] });
        }
      } catch {
        parts.push({ type: 'text', content: match[0] });
      }
      lastIndex = match.index + match[0].length;
    }

    // Remaining text
    if (lastIndex < content.length) {
      parts.push({ type: 'text', content: content.slice(lastIndex) });
    }

    return parts;
  };

  /** Apply a suggestion to a rule — validate field against allowlist */
  const VALID_SUGGESTION_FIELDS = new Set([
    'name', 'action', 'description', 'src_zones', 'dst_zones',
    'src_addresses', 'dst_addresses', 'source_users', 'applications',
    'services', 'log_start', 'log_end', 'disabled', 'profile_group',
    'security_profiles', 'tags', 'schedule', 'negate_source', 'negate_destination',
  ]);

  const handleAcceptSuggestion = (suggestion) => {
    if (!intermediateConfig || !onUpdateRule) return;
    if (!VALID_SUGGESTION_FIELDS.has(suggestion.field)) return;
    const policies = intermediateConfig.security_policies || [];
    const index = policies.findIndex(r => r.name === suggestion.rule_name);
    if (index < 0) return;

    const rule = { ...policies[index], [suggestion.field]: suggestion.suggested };
    onUpdateRule(index, rule);
  };

  /** Format a value for display */
  const formatValue = (val) => {
    if (val === true) return 'true';
    if (val === false) return 'false';
    if (Array.isArray(val)) return val.join(', ');
    if (val === null || val === undefined) return '(none)';
    return String(val);
  };

  return (
    <div className="panel interview-panel review-chat-panel">
      <div className="panel-header">
        <h2>Review with LLM</h2>
        <button className="btn btn-secondary btn-sm" onClick={onExitReview}>
          Back to Rules
        </button>
      </div>

      {/* Messages area */}
      <div className="chat-messages">
        {messages.map((msg, i) => (
          <div key={i} className={`chat-message ${msg.role}`}>
            {msg.role === 'assistant' ? (
              // Parse assistant messages for inline suggestions
              parseMessageContent(msg.content).map((part, j) => {
                if (part.type === 'suggestion') {
                  return (
                    <div key={j} className="chat-suggestion-card">
                      <div className="suggestion-field-name">
                        {part.data.rule_name} &mdash; {part.data.field}
                      </div>
                      <div className="suggestion-values">
                        <span className="suggestion-current">{formatValue(part.data.current)}</span>
                        <span className="suggestion-arrow">&rarr;</span>
                        <span className="suggestion-new">{formatValue(part.data.suggested)}</span>
                      </div>
                      {part.data.reason && (
                        <div className="suggestion-reason">{part.data.reason}</div>
                      )}
                      <div className="chat-suggestion-actions">
                        <button
                          className="suggestion-import-btn"
                          onClick={() => handleAcceptSuggestion(part.data)}
                        >
                          Accept
                        </button>
                      </div>
                    </div>
                  );
                }
                return <span key={j} style={{ whiteSpace: 'pre-wrap' }}>{part.content}</span>;
              })
            ) : (
              <span style={{ whiteSpace: 'pre-wrap' }}>
                {/* Show abbreviated user message for the initial prompt */}
                {i === 0 && msg.content.length > 200
                  ? 'Reviewing full ruleset...'
                  : msg.content}
              </span>
            )}
          </div>
        ))}

        {isLoading && (
          <div className="chat-message assistant" style={{ opacity: 0.7 }}>
            <span className="loading-spinner" style={{ width: 14, height: 14 }} />
            <span style={{ marginLeft: 8 }}>Analyzing...</span>
          </div>
        )}

        {error && (
          <div className="suggestion-error" style={{ margin: '0 0 8px 0' }}>
            {error}
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Input area */}
      <div className="chat-input-area">
        <textarea
          className="chat-input"
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Ask a follow-up question..."
          rows={1}
          disabled={isLoading}
        />
        <button
          className="btn btn-primary btn-sm"
          onClick={handleSend}
          disabled={isLoading || !inputText.trim()}
        >
          Send
        </button>
      </div>
    </div>
  );
}
