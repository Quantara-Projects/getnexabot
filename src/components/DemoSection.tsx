import { useState, useRef, useEffect } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Send, User, Info } from "lucide-react";
import { LogoIcon } from "@/components/ui/logo";

interface Message {
  type: "user" | "bot";
  message: string;
}

const DemoSection = () => {
  const [messages, setMessages] = useState<Message[]>([
    {
      type: "bot",
      message:
        "Hi! I am NexaBot. Ask me anything about our platform, features, or how we can help your business.",
    },
  ]);
  const [inputValue, setInputValue] = useState("");
  const [isTyping, setIsTyping] = useState(false);
  const chatScrollRef = useRef<HTMLDivElement>(null);

  // System prompt that tells the AI who it is and what its rules are
  const SYSTEM_PROMPT = `You are NexaBot, an AI-powered customer support assistant for a platform called NexaBot. 

ABOUT NEXABOT:
NexaBot is an AI-powered customer support and automation platform that helps businesses create intelligent chatbots for websites, online stores, communities, and messaging platforms. Designed for speed, scalability, and simplicity, NexaBot enables businesses to deliver instant 24/7 responses, automate repetitive tasks, capture leads, and improve customer engagement without needing a technical team.

KEY FEATURES:
- Website widget, WhatsApp, Messenger, Slack, Discord integration
- AI-powered 24/7 customer support
- Lead capture and automated notifications
- Custom AI training using FAQs, documents, website content, or company knowledge
- Omnichannel deployment from one dashboard
- No-code setup and easy onboarding
- Analytics and conversation insights
- Enterprise-grade security and privacy
- Web3 subscription payments
- Support for zkLTC and LitVM chain payments

YOUR PERSONALITY & RULES:
- You are helpful, concise, and professional
- You answer questions about NexaBot's features, pricing, setup process, integrations, and capabilities
- If asked something outside of NexaBot's scope, politely redirect to NexaBot topics
- Keep responses under 3 sentences when possible
- Be enthusiastic about helping businesses
- Do NOT make up features or capabilities not listed
- Do NOT use emojis
- Keep responses factual and clear

RESPONSE FORMAT:
- Answer directly and concisely
- Use plain, professional language
- No markdown formatting needed`;

  useEffect(() => {
    // Keep scrolling contained inside the chat panel (avoid scrolling the page)
    const el = chatScrollRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
  }, [messages]);

  const sampleQuestions = [
    "Do you offer 24/7 support?",
    "What platforms do you integrate with?",
    "How long does setup take?",
    "Can I train it on my data?",
  ];

  const callOpenRouter = async (userMessage: string): Promise<string> => {
    try {
      const response = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: userMessage,
          systemPrompt: SYSTEM_PROMPT,
        }),
      });

      if (!response.ok) {
        throw new Error("API request failed");
      }

      const data = await response.json();
      return data.reply;
    } catch (error) {
      console.error("OpenRouter error:", error);
      return "I apologize, but I am having trouble connecting right now. Please try again in a moment.";
    }
  };

  const handleSendMessage = async (message?: string) => {
    const messageToSend = message || inputValue;
    if (!messageToSend.trim()) return;

    setMessages((prev) => [...prev, { type: "user", message: messageToSend }]);
    setInputValue("");
    setIsTyping(true);

    try {
      const response = await callOpenRouter(messageToSend);
      setMessages((prev) => [...prev, { type: "bot", message: response }]);
    } catch {
      setMessages((prev) => [
        ...prev,
        {
          type: "bot",
          message:
            "I apologize, but I encountered an error. Please try asking your question again.",
        },
      ]);
    } finally {
      setIsTyping(false);
    }
  };

  return (
    <section id="demo" className="py-24 bg-secondary/20 relative">
      {/* Background decoration */}
      <div className="absolute inset-0">
        <div className="absolute bottom-0 right-0 w-[400px] h-[400px] bg-gradient-radial from-primary/5 to-transparent rounded-full blur-3xl" />
      </div>

      <div className="container mx-auto px-6 relative z-10">
        {/* Section Header */}
        <div className="text-center mb-16 max-w-2xl mx-auto space-y-4 animate-fade-up">
          <h2 className="text-4xl lg:text-5xl font-bold tracking-tight text-foreground">
            Try NexaBot
            <span className="gradient-text block">Live Demo</span>
          </h2>
          <p className="text-lg text-neutral-500 leading-relaxed">
            Experience the power of instant AI responses. Ask any question and
            see how NexaBot would handle it for your business.
          </p>
        </div>

        <div
          className="max-w-4xl mx-auto animate-fade-up"
          style={{ animationDelay: "0.1s" }}
        >
          <Card className="border-border/40 shadow-xl overflow-hidden">
            <CardContent className="p-0">
              <div className="grid grid-cols-1 lg:grid-cols-5">
                {/* Chat Interface */}
                <div className="lg:col-span-3 p-6 border-b lg:border-b-0 lg:border-r border-border/30">
                  {/* Chat Header */}
                  <div className="flex items-center justify-between pb-4 border-b border-border/30 mb-4">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-full gradient-bg flex items-center justify-center shadow-sm">
                        <svg viewBox="0 0 20 20" className="w-5 h-5 fill-white">
                          <path d="M10 1L17.5 5.5V14.5L10 19L2.5 14.5V5.5L10 1Z" />
                          <path
                            d="M10 3.5L15 6.5V13.5L10 16.5L5 13.5V6.5L10 3.5Z"
                            className="fill-primary/20"
                          />
                        </svg>
                      </div>
                      <div>
                        <div className="text-sm font-semibold text-foreground">
                          NexaBot Live
                        </div>
                        <div className="flex items-center gap-1.5">
                          <div className="w-1.5 h-1.5 rounded-full bg-success-500 animate-pulse" />
                          <span className="text-xs text-neutral-400">
                            AI Powered
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-primary/8 border border-primary/15 text-primary text-xs font-medium">
                      <Info className="w-3 h-3" />
                      <span>Live</span>
                    </div>
                  </div>

                  {/* Chat Messages */}
                  <div
                    ref={chatScrollRef}
                    className="space-y-4 mb-4 h-[340px] overflow-y-auto custom-scrollbar pr-1"
                  >
                    {messages.map((msg, index) => (
                      <div
                        key={index}
                        className={`flex items-end gap-2 ${
                          msg.type === "user" ? "justify-end" : "justify-start"
                        } animate-fade-up`}
                        style={{ animationDelay: `${index * 0.05}s` }}
                      >
                        {msg.type === "bot" && (
                          <div className="w-8 h-8 rounded-xl bg-primary/10 border border-primary/15 flex items-center justify-center flex-shrink-0">
                            <LogoIcon className="w-5 h-5" />
                          </div>
                        )}

                        <div
                          className={`max-w-[85%] p-3 rounded-xl ${
                            msg.type === "user"
                              ? "bg-primary text-white rounded-br-md shadow-sm"
                              : "bg-secondary rounded-bl-md border border-border/30"
                          }`}
                        >
                          <p className="text-sm leading-relaxed">
                            {msg.message}
                          </p>
                        </div>

                        {msg.type === "user" && (
                          <div className="w-8 h-8 rounded-xl bg-primary flex items-center justify-center flex-shrink-0 shadow-sm">
                            <User className="w-4 h-4 text-white/80" />
                          </div>
                        )}
                      </div>
                    ))}
                  </div>

                  {/* Chat Input */}
                  <div className="space-y-2.5">
                    <div className="flex items-center gap-2">
                      <Input
                        value={inputValue}
                        onChange={(e) => setInputValue(e.target.value)}
                        placeholder="Ask NexaBot anything..."
                        className="flex-1 border-border/50 focus-visible:ring-primary/30 bg-background"
                        onKeyDown={(e) =>
                          e.key === "Enter" && !isTyping && handleSendMessage()
                        }
                        disabled={isTyping}
                      />
                      <Button
                        size="sm"
                        onClick={() => handleSendMessage()}
                        disabled={!inputValue.trim() || isTyping}
                        className="bg-primary text-white hover:bg-primary/90 shadow-sm disabled:opacity-50 h-10 w-10 p-0"
                      >
                        <Send className="w-4 h-4" />
                      </Button>
                    </div>

                    <p className="text-xs text-neutral-400 text-center">
                      This demo uses AI. Responses are generated in real-time.
                    </p>
                  </div>
                </div>

                {/* Quick Questions Panel */}
                <div className="lg:col-span-2 p-6 bg-secondary/20">
                  <div className="space-y-4">
                    <div>
                      <h4 className="text-sm font-semibold text-foreground mb-1">
                        Try asking:
                      </h4>
                      <p className="text-xs text-neutral-400">
                        Click a question to see NexaBot respond
                      </p>
                    </div>

                    <div className="space-y-2.5">
                      {sampleQuestions.map((question, index) => (
                        <Button
                          key={index}
                          variant="outline"
                          className="w-full justify-start text-left h-auto p-3 text-sm font-normal border-border/50 hover:border-primary/30 hover:bg-primary/5 transition-all"
                          onClick={() => handleSendMessage(question)}
                          disabled={isTyping}
                        >
                          {question}
                        </Button>
                      ))}
                    </div>

                    <div className="mt-6 p-4 rounded-xl bg-primary/5 border border-primary/10">
                      <div className="flex items-start gap-3">
                        <LogoIcon className="w-5 h-5 mt-0.5 flex-shrink-0" />
                        <div className="text-sm">
                          <p className="font-medium text-foreground mb-1">
                            Powered by AI
                          </p>
                          <p className="text-neutral-500 leading-relaxed text-xs">
                            NexaBot learns from your business data to provide
                            accurate, personalized responses for your customers.
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </section>
  );
};

export default DemoSection;
