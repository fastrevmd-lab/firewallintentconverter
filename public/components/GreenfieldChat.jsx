/**
 * GreenfieldChat Component
 *
 * LLM-guided interview for building an SRX configuration from scratch.
 * Uses multi-turn chat with the greenfield system prompt. The LLM emits
 * JSON action blocks that progressively build the intermediateConfig.
 *
 * Renders inside the center panel (no outer panel wrapper).
 */
import React, { useState, useEffect, useRef } from 'react';
import {
  getLLMChatResponse,
  getLLMStatus,
  loadSystemPrompt,
} from '../utils/llm-client.js';

export default function GreenfieldChat({
  intermediateConfig,
  targetModel,
  srxLicense,
  greenfieldTemplate,
  onApplyAction,
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

  // Auto-send initial greeting once targetModel is available (after ModelSelector closes)
  useEffect(() => {
    if (hasInitialized.current) return;
    if (!targetModel) return; // Wait for model selection

    hasInitialized.current = true;

    if (!llmStatus.configured) {
      setError('No LLM provider configured. Open Settings to configure one.');
      return;
    }

    sendInitialGreeting();
  }, [targetModel]);

  /** Send the initial prompt to kick off the interview */
  const sendInitialGreeting = async () => {
    const targetInfo = targetModel ? ` for a ${targetModel}` : '';
    const licenseInfo = srxLicense ? ` with ${srxLicense} subscription` : '';

    let content;
    if (greenfieldTemplate && greenfieldTemplate !== 'blank') {
      const cfg = intermediateConfig;
      const zoneNames = (cfg.zones || []).map(z => z.name).join(', ');
      const policyCount = cfg.security_policies?.length || 0;
      const natCount = cfg.nat_rules?.length || 0;
      const sysHost = cfg.system_config?.hostname || 'not set';
      content = `I have loaded the "${greenfieldTemplate}" template${targetInfo}${licenseInfo}. ` +
        `The template pre-configured: ${cfg.zones?.length || 0} zones (${zoneNames}), ` +
        `${policyCount} security policies, ${natCount} NAT rules, ` +
        `hostname "${sysHost}", and basic system settings (DNS, NTP, screen profiles, syslog). ` +
        `Please briefly review what's configured and ask what I'd like to customize or add.`;
    } else {
      content = `I need to build a new Juniper SRX firewall configuration from scratch${targetInfo}${licenseInfo}. ` +
        `Please help me through a guided interview to set up the configuration. Start by asking about my deployment use case.`;
    }

    const userMsg = { role: 'user', content };

    setMessages([userMsg]);
    setIsLoading(true);
    setError('');

    try {
      const systemPrompt = loadSystemPrompt('greenfield');
      const response = await getLLMChatResponse([userMsg], systemPrompt);
      const assistantMsg = { role: 'assistant', content: response };
      setMessages(prev => [...prev, assistantMsg]);
      processActionBlocks(response);
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
      const systemPrompt = loadSystemPrompt('greenfield');
      const response = await getLLMChatResponse(updatedMessages, systemPrompt);
      const assistantMsg = { role: 'assistant', content: response };
      setMessages(prev => [...prev, assistantMsg]);
      processActionBlocks(response);
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

  /** Extract and auto-apply JSON action blocks from LLM response */
  const processActionBlocks = (content) => {
    const regex = /```json\s*\n?([\s\S]*?)\n?\s*```/g;
    let match;
    while ((match = regex.exec(content)) !== null) {
      try {
        const json = JSON.parse(match[1].trim());
        if (json.action && json.data) {
          onApplyAction(json.action, json.data);
        }
      } catch { /* ignore unparseable blocks */ }
    }
  };

  /** Parse message content for display — highlights action blocks as cards */
  const parseMessageContent = (content) => {
    const parts = [];
    const regex = /```json\s*\n?([\s\S]*?)\n?\s*```/g;
    let lastIndex = 0;
    let match;

    while ((match = regex.exec(content)) !== null) {
      if (match.index > lastIndex) {
        parts.push({ type: 'text', content: content.slice(lastIndex, match.index) });
      }
      try {
        const json = JSON.parse(match[1].trim());
        if (json.action && json.data) {
          parts.push({ type: 'action', data: json });
        } else {
          parts.push({ type: 'text', content: match[0] });
        }
      } catch {
        parts.push({ type: 'text', content: match[0] });
      }
      lastIndex = match.index + match[0].length;
    }

    if (lastIndex < content.length) {
      parts.push({ type: 'text', content: content.slice(lastIndex) });
    }

    return parts;
  };

  /** Friendly label for action type */
  const actionLabel = (action) => {
    const labels = {
      add_zone: 'Zone',
      add_address: 'Address',
      add_address_group: 'Address Group',
      add_service: 'Service',
      add_policy: 'Security Policy',
      add_nat: 'NAT Rule',
      add_screen: 'Screen Profile',
      set_syslog: 'Syslog',
      add_route: 'Static Route',
      set_system: 'System Config',
    };
    return labels[action] || action;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, overflow: 'hidden' }}>
      {/* Messages area */}
      <div className="chat-messages" style={{ flex: 1, overflow: 'auto', padding: '12px' }}>
        {messages.map((msg, i) => (
          <div key={i} className={`chat-message ${msg.role}`}>
            {msg.role === 'assistant' ? (
              parseMessageContent(msg.content).map((part, j) => {
                if (part.type === 'action') {
                  return (
                    <div key={j} style={{
                      margin: '8px 0',
                      padding: '8px 12px',
                      background: 'rgba(34, 197, 94, 0.08)',
                      border: '1px solid rgba(34, 197, 94, 0.25)',
                      borderRadius: 'var(--radius)',
                      fontSize: 12,
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                        <span style={{
                          padding: '2px 6px',
                          background: 'rgba(34, 197, 94, 0.15)',
                          borderRadius: 'var(--radius)',
                          fontSize: 10,
                          fontWeight: 600,
                          color: 'var(--success)',
                          textTransform: 'uppercase',
                        }}>
                          {actionLabel(part.data.action)}
                        </span>
                        <span style={{
                          fontSize: 10,
                          color: 'var(--success)',
                          marginLeft: 'auto',
                          fontWeight: 500,
                        }}>
                          Applied
                        </span>
                      </div>
                      <div style={{ fontWeight: 500 }}>{part.data.data?.name || part.data.data?.hostname || ''}</div>
                      {part.data.data?.description && (
                        <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
                          {part.data.data.description}
                        </div>
                      )}
                    </div>
                  );
                }
                return <span key={j} style={{ whiteSpace: 'pre-wrap' }}>{part.content}</span>;
              })
            ) : (
              <span style={{ whiteSpace: 'pre-wrap' }}>
                {i === 0 && msg.content.length > 200
                  ? 'Starting greenfield SRX configuration interview...'
                  : msg.content}
              </span>
            )}
          </div>
        ))}

        {isLoading && (
          <div className="chat-message assistant" style={{ opacity: 0.7 }}>
            <span className="loading-spinner" style={{ width: 14, height: 14 }} />
            <span style={{ marginLeft: 8 }}>Thinking...</span>
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
          placeholder="Type your answer..."
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
