import React, { useEffect, useState } from 'react';
import {fetchData} from '../App';
import './ChatBot.css'
import '../App.css'
import {useNavigate} from 'react-router-dom';

export function ChatBot() {
  const [userid, setUserid] = useState('');
  const [input, setInput] = useState('');
  const [messages, setMessages] = useState([]);
  const [threads, setThreads] = useState([]);
  const [currentThreadId, setCurrentThreadId] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isSending, setIsSending] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    fetchData('/users', "GET").then((response) => {
      setUserid(response.id);
      // Load user's threads after getting userid
      loadUserThreads(response.id);
    }).catch((e) => {
      console.log("Cannot get userid.");
      navigate("/login");
    })
  }, [navigate]);

  // Load all threads for the current user
  async function loadUserThreads() {
    try {
      setIsLoading(true);
      const response = await fetchData(`/users`, "GET");
      console.log(response)
      setThreads(response.thread_ids || []);
      
      // Auto-select first thread if available
      if (response.thread_ids && response.thread_ids.length > 0) {
        const firstThread = response.thread_ids[0];
        setCurrentThreadId(firstThread);
        await loadMessageHistory(firstThread);
      } else {
        setThreads([-1])
      }
    } catch (error) {
      console.error("Failed to load threads:", error);
    } finally {
      setIsLoading(false);
    }
  }

  // Load message history for a specific thread
  async function loadMessageHistory(threadId) {
    if (threadId === -1) {
      setMessages([]);
      return;
    }
    try {
      setIsLoading(true);
      console.log("is trying")
      const response = await fetchData(`/orchestrate/threads/${threadId}`, "GET");
      console.log(response)
      setMessages(response || []);
    } catch (error) {
      console.error("Failed to load message history:", error);
      setMessages([]);
    } finally {
      setIsLoading(false);
    }
  }

  // Handle thread selection
  async function selectThread(threadId) {
    if (threadId === currentThreadId) return;
    
    setCurrentThreadId(threadId);
    await loadMessageHistory(threadId);
  }

  // Create a new thread
  async function createNewThread() {
    try {
      setThreads([...threads, -1]);
      setCurrentThreadId(-1);
      await loadMessageHistory(-1);
    } catch (error) {
      console.error("Failed to create new thread:", error);
    }
  }

  // Send message and get response
  async function sendMessage() {
    if (!input.trim() || !currentThreadId || isSending) return;

    const userMessage = {
      id: Date.now(),
      message: input.trim(),
      is_user: true,
      timestamp: new Date().toISOString()
    };

    // Add user message to chat immediately
    setMessages(prev => [...prev, userMessage]);
    const messageContent = input.trim();
    setInput('');
    setIsSending(true);
    
    try {
      // Send message to API
      const response = await fetchData('/orchestrate/message', "POST", {
        thread_id: currentThreadId===-1?null:currentThreadId,
        message: messageContent
      });
      await loadUserThreads();
      setCurrentThreadId(response.thread_id)
      await loadMessageHistory(currentThreadId);
    } catch (error) {
      console.error("Failed to send message:", error);
      // Add error message to chat
      const errorMessage = {
        id: Date.now() + 1,
        message: "Sorry, there was an error sending your message. Please try again.",
        is_user: false,
        timestamp: new Date().toISOString(),
        isError: true
      };
      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setIsSending(false);
    }
  }

  // Handle Enter key press
  function handleKeyPress(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  }

  return (
    <>
      <div className="sub-container chat-container outer">
        {/* Thread list sidebar */}
        <div className="chat-container thread">
          <div className="thread-header">
            <h3>Conversations</h3>
            <button 
              onClick={createNewThread}
              className="new-thread-button"
              disabled={!userid}
            >
              + New Chat
            </button>
          </div>
          
          <div className="thread-list">
            {isLoading && threads.length === 0 ? (
              <div className="loading">Loading threads...</div>
            ) : (
              threads.map((thread, index) => (
                <div
                  key={index}
                  className={`thread-item ${currentThreadId === thread ? 'active' : ''}`}
                  onClick={() => selectThread(thread)}
                >
                  <div className="thread-title">
                    {thread.title || `Chat ${index}`}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Main chat area */}
        <div className="chat-container inner">
          {/* Messages display */}
          <div className="messages-container">
            {isLoading && messages.length === 0 ? (
              <div className="loading">Loading messages...</div>
            ) : messages.length === 0 ? (
              <div className="empty-chat">
                <p>Start a new conversation!</p>
              </div>
            ) : (
              messages.map((message) => (
                <div
                  key={message.timestamp}
                  className={`message ${message.is_user ? 'user-message' : 'bot-message'} ${message.isError ? 'error-message' : ''}`}
                >
                  <div className="message-content">
                    {message.message}
                  </div>
                  <div className="message-timestamp">
                    {new Date(message.timestamp).toLocaleTimeString()}
                  </div>
                </div>
              ))
            )}
            
            {/* Loading indicator for bot response */}
            {isSending && (
              <div className="message bot-message">
                <div className="message-content typing-indicator">
                  <span></span>
                  <span></span>
                  <span></span>
                </div>
              </div>
            )}
          </div>

          {/* Input area */}
          <div className="chat-container input">
            <input 
              type="text"
              placeholder={currentThreadId ? "Type your message..." : "Select or create a thread to start chatting"}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyPress={handleKeyPress}
              disabled={!currentThreadId || isSending}
            />
            <button
              type="button"
              onClick={sendMessage}
              className="chat-submit-button"
              disabled={!input.trim() || !currentThreadId || isSending}
            >
              {isSending ? '...' : 'Send'}
            </button>
          </div>
        </div>
      </div>
    </>
  )
}