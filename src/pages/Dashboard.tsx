import { useState, useEffect, useMemo, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";
import {
  Bot,
  MessageSquare,
  Zap,
  Settings,
  Upload,
  Link,
  Smartphone,
  Globe,
  BarChart3,
  CheckCircle,
  Clock,
  Image,
  Palette,
  Copy,
  Check,
  LayoutDashboard,
  BotMessageSquare,
  Activity,
  User,
  LogOut,
  ChevronLeft,
  ChevronRight,
  Menu,
  X,
  Sparkles,
  FileText,
  GraduationCap,
  Shield,
  Rocket,
  CreditCard,
  Code2,
  Monitor,
  KeyRound,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { LogoIcon, LogoText } from "@/components/ui/logo";

interface UploadedItem {
  id: string;
  name: string;
  size: number;
  type: string;
  file?: File;
}

interface BotRecord {
  id?: string;
  bot_id: string;
  public_api_key?: string;
  channel?: string;
  domain?: string;
  runtime_mode?: string;
  status?: string;
  settings?: any;
  created_at?: string;
}

// Basic URL validation
const isValidHttpUrl = (value: string) => {
  try {
    const u = new URL(value);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
};

const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024;
const ACCEPTED_MIMES = [
  "application/pdf",
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "text/plain",
];

type SidebarView = "overview" | "bots" | "features" | "settings" | "profile";
type ExtendedSidebarView = SidebarView | "subscription";
type RuntimeMode = "live" | "localhost" | "both";
type WidgetPosition = "bottom-right" | "bottom-left" | "top-right" | "top-left";

const Dashboard = () => {
  const navigate = useNavigate();
  const { user, signOut } = useAuth();
  const { toast } = useToast();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [copied, setCopied] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [sidebarView, setSidebarView] =
    useState<ExtendedSidebarView>("overview");
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const [businessName, setBusinessName] = useState("Your Company");

  // Wizard state
  const [websiteUrl, setWebsiteUrl] = useState("");
  const [runtimeMode, setRuntimeMode] = useState<RuntimeMode>("live");
  const [companyDescription, setCompanyDescription] = useState("");
  const [uploadedFiles, setUploadedFiles] = useState<UploadedItem[]>([]);
  const [training, setTraining] = useState({
    inProgress: false,
    progress: 0,
    completed: false,
    error: null as string | null,
  });
  const [selectedChannel, setSelectedChannel] = useState<string | null>(null);
  const [botId, setBotId] = useState<string | null>(null);
  const [publicApiKey, setPublicApiKey] = useState<string | null>(null);
  const [embedCode, setEmbedCode] = useState<string | null>(null);
  const [setupStep, setSetupStep] = useState(1);
  const [bots, setBots] = useState<BotRecord[]>([]);
  const [launching, setLaunching] = useState(false);
  const [widgetTitle, setWidgetTitle] = useState("NexaBot");
  const [widgetSubtitle, setWidgetSubtitle] = useState("AI support assistant");
  const [widgetLogoUrl, setWidgetLogoUrl] = useState("");
  const [widgetButtonLabel, setWidgetButtonLabel] = useState("Chat");
  const [widgetPosition, setWidgetPosition] =
    useState<WidgetPosition>("bottom-right");
  const [widgetColor, setWidgetColor] = useState("#22d3c8");

  useEffect(() => {
    const loadName = async () => {
      try {
        const metaName = (user as any)?.user_metadata?.business_name;
        if (metaName) {
          setBusinessName(metaName);
          return;
        }
        if (user) {
          const { data } = await supabase
            .from("profiles")
            .select("business_name")
            .eq("user_id", user.id)
            .limit(1)
            .single();
          if (data?.business_name) setBusinessName(data.business_name);
        }
      } catch {}
    };
    loadName();
  }, [user]);

  const loadBots = async () => {
    if (!user) return;
    try {
      const { data } = await supabase
        .from("chatbot_configs")
        .select("*")
        .eq("user_id", user.id)
        .order("created_at", { ascending: false });
      if (Array.isArray(data)) setBots(data as BotRecord[]);
    } catch {}
  };

  useEffect(() => {
    loadBots();
  }, [user]);

  const handleLogout = async () => {
    try {
      await signOut();
      localStorage.removeItem("wizard_state");
      localStorage.removeItem("app_settings");
      navigate("/");
    } catch {}
  };

  const sidebarItems: { icon: any; label: string; view: ExtendedSidebarView }[] = [
    { icon: LayoutDashboard, label: "Overview", view: "overview" },
    { icon: Bot, label: "Bots", view: "bots" },
    { icon: BotMessageSquare, label: "Features", view: "features" },
    { icon: CreditCard, label: "Subscription", view: "subscription" },
    { icon: Settings, label: "Settings", view: "settings" },
    { icon: User, label: "Profile", view: "profile" },
  ];

  const onFilesSelected = (files: FileList | null) => {
    if (!files) return;
    const accepted: UploadedItem[] = [];
    for (const f of Array.from(files)) {
      if (!ACCEPTED_MIMES.includes(f.type)) {
        toast({
          title: "Unsupported file type",
          description: `${f.name} was rejected.`,
          variant: "destructive",
        });
        continue;
      }
      if (f.size > MAX_FILE_SIZE_BYTES) {
        toast({
          title: "File too large",
          description: `${f.name} exceeds 10MB.`,
          variant: "destructive",
        });
        continue;
      }
      accepted.push({
        id: `${f.name}-${f.size}-${f.lastModified}`,
        name: f.name,
        size: f.size,
        type: f.type,
        file: f,
      });
    }
    if (accepted.length) {
      setUploadedFiles((prev) => [...prev, ...accepted]);
    }
  };

  const onDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    onFilesSelected(e.dataTransfer.files);
  };

  const getDomain = (url: string) => {
    try {
      return new URL(url).host.toLowerCase();
    } catch {
      return "";
    }
  };

  const createPublicApiKey = () => {
    const random = crypto.getRandomValues(new Uint8Array(24));
    return `nxb_${Array.from(random, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
  };

  const buildEmbedCode = (apiKey: string, id: string) => {
    const origin = window.location.origin;
    return `<script async src="${origin}/api/nexabot" data-bot-id="${id}" data-api-key="${apiKey}"></script>`;
  };

  const widgetSettings = useMemo(
    () => ({
      title: widgetTitle.trim() || "NexaBot",
      subtitle: widgetSubtitle.trim() || "AI support assistant",
      logoUrl: widgetLogoUrl.trim(),
      buttonLabel: widgetButtonLabel.trim() || "Chat",
      position: widgetPosition,
      primaryColor: widgetColor,
      runtimeMode,
      companyDescription: companyDescription.trim(),
    }),
    [
      widgetTitle,
      widgetSubtitle,
      widgetLogoUrl,
      widgetButtonLabel,
      widgetPosition,
      widgetColor,
      runtimeMode,
      companyDescription,
    ]
  );

  const startTraining = async () => {
    if (!websiteUrl.trim() || !isValidHttpUrl(websiteUrl)) {
      toast({
        title: "Website URL required",
        description: "Enter a valid website URL before training.",
        variant: "destructive",
      });
      return;
    }
    if (!companyDescription.trim()) {
      toast({
        title: "Company description required",
        description: "Add instructions and company information for the AI.",
        variant: "destructive",
      });
      return;
    }

    setTraining({ inProgress: true, progress: 20, completed: false, error: null });

    try {
      const id = makeLocalBotId(websiteUrl, user?.id || "local");
      const apiKey = publicApiKey || createPublicApiKey();
      setBotId(id);
      setPublicApiKey(apiKey);
      setEmbedCode(buildEmbedCode(apiKey, id));

      if (user) {
        await supabase.from("chatbot_configs").upsert(
          {
            bot_id: id,
            user_id: user.id,
            channel: "website",
            domain: getDomain(websiteUrl),
            public_api_key: apiKey,
            runtime_mode: runtimeMode,
            status: "draft",
            settings: widgetSettings,
          },
          { onConflict: "bot_id" }
        );
        await supabase.from("training_documents").insert({
          bot_id: id,
          user_id: user.id,
          source: "manual-description",
          content: companyDescription.trim(),
        });
      }

      setTraining({ inProgress: false, progress: 100, completed: true, error: null });
      toast({
        title: "Training saved",
        description: "NexaBot will use your website and company instructions.",
      });
      setSetupStep(2);
    } catch {
      setTraining({
        inProgress: false,
        progress: 0,
        completed: false,
        error: "Training failed",
      });
      toast({
        title: "Training failed",
        description: "Please check your details and try again.",
        variant: "destructive",
      });
    }
  };

  const makeLocalBotId = (url: string, owner: string) => {
    const seed = `${url}|${owner}|${Date.now()}`;
    let hash = 0;
    for (let i = 0; i < seed.length; i += 1) hash = (hash * 31 + seed.charCodeAt(i)) >>> 0;
    return `bot_${hash.toString(16)}_${Date.now().toString(36)}`;
  };

  const chooseWebsiteChannel = () => {
    setSelectedChannel("Website Chat");
    setSetupStep(3);
  };

  const saveBot = async () => {
    if (!user || !botId || !publicApiKey || !embedCode) return;
    setLaunching(true);
    try {
      const domain = getDomain(websiteUrl);
      const record = {
        bot_id: botId,
        user_id: user.id,
        channel: "website",
        domain,
        public_api_key: publicApiKey,
        runtime_mode: runtimeMode,
        status: "active",
        settings: widgetSettings,
      };
      const { error } = await supabase
        .from("chatbot_configs")
        .upsert(record, { onConflict: "bot_id" });
      if (error) throw error;
      toast({
        title: "Bot confirmed",
        description: "Your chatbot is now available in Bots.",
      });
      await loadBots();
      setSidebarView("bots");
    } catch {
      toast({
        title: "Could not save bot",
        description: "Check your Supabase tables and try again.",
        variant: "destructive",
      });
    } finally {
      setLaunching(false);
    }
  };

  const renderSidebar = () => (
    <div
      className={`h-full flex flex-col bg-sidebar-background border-r border-border/40 ${sidebarOpen ? "w-60" : "w-16"} transition-all duration-300`}
    >
      {/* Logo */}
      <div className="flex items-center justify-between p-4 border-b border-border/30">
        {sidebarOpen ? (
          <div
            className="flex items-center gap-2.5 cursor-pointer"
            onClick={() => navigate("/")}
          >
            <LogoIcon className="w-8 h-8" />
            <LogoText className="text-base" />
          </div>
        ) : (
          <LogoIcon
            className="w-8 h-8 mx-auto cursor-pointer"
            onClick={() => navigate("/")}
          />
        )}
        <button
          onClick={() => setSidebarOpen(!sidebarOpen)}
          className="hidden lg:flex p-1.5 rounded-lg hover:bg-sidebar-accent transition-smooth"
        >
          {sidebarOpen ? (
            <ChevronLeft className="w-4 h-4" />
          ) : (
            <ChevronRight className="w-4 h-4" />
          )}
        </button>
      </div>

      {/* Navigation items */}
      <div className="flex-1 py-4 space-y-1 px-3">
        {sidebarItems.map((item) => (
          <button
            key={item.view}
            onClick={() => setSidebarView(item.view)}
            className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all text-sm font-medium ${
              sidebarView === item.view
                ? "bg-primary/10 text-primary"
                : "text-sidebar-foreground hover:bg-sidebar-accent"
            }`}
          >
            <item.icon className="w-5 h-5 flex-shrink-0" />
            {sidebarOpen && <span>{item.label}</span>}
          </button>
        ))}
      </div>

      {/* User area */}
      <div className="p-3 border-t border-border/30">
        <button
          onClick={handleLogout}
          className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm text-neutral-500 hover:bg-sidebar-accent hover:text-foreground transition-all"
        >
          <LogOut className="w-5 h-5 flex-shrink-0" />
          {sidebarOpen && <span>Sign Out</span>}
        </button>
      </div>
    </div>
  );

  const renderContent = () => {
    switch (sidebarView) {
      case "overview":
        return renderOverview();
      case "bots":
        return renderBots();
      case "features":
        return renderFeatures();
      case "subscription":
        return renderSubscription();
      case "settings":
        return renderSettings();
      case "profile":
        return renderProfile();
      default:
        return renderOverview();
    }
  };

  const renderOverview = () => (
    <div className="space-y-6 animate-fade-up">
      {/* Welcome Banner */}
      <Card className="border-primary/15 bg-gradient-to-br from-primary/5 to-cyan-400/5">
        <CardContent className="p-6">
          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <h2 className="text-2xl font-bold text-foreground">
                Welcome back, {businessName}
              </h2>
              <p className="text-sm text-neutral-500">
                Your NexaBot is ready to configure. Let us get you set up in 3
                simple steps.
              </p>
            </div>
            <div className="hidden md:block">
              <div className="w-14 h-14 rounded-2xl gradient-bg flex items-center justify-center shadow-sm">
                <Bot className="w-7 h-7 text-white" />
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Setup Wizard */}
      <Card className="border-border/40">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2 text-lg">
              <Zap className="w-5 h-5 text-primary" />
              Setup Wizard
            </CardTitle>
            <Badge
              variant="secondary"
              className="bg-primary/10 text-primary border-primary/20"
            >
              Step {setupStep} of 3
            </Badge>
          </div>
          <Progress value={(setupStep / 3) * 100} className="h-1.5" />
        </CardHeader>
        <CardContent>
          <Tabs value={`step-${setupStep}`}>
            <TabsList className="grid grid-cols-3 mb-6">
              <TabsTrigger value="step-1" disabled className="gap-2">
                <Upload className="w-4 h-4" />{" "}
                <span className="hidden sm:inline">Train Bot</span>
              </TabsTrigger>
              <TabsTrigger value="step-2" disabled className="gap-2">
                <Link className="w-4 h-4" />{" "}
                <span className="hidden sm:inline">Connect</span>
              </TabsTrigger>
              <TabsTrigger value="step-3" disabled className="gap-2">
                <CheckCircle className="w-4 h-4" />{" "}
                <span className="hidden sm:inline">Launch</span>
              </TabsTrigger>
            </TabsList>

            <TabsContent value="step-1" className="space-y-4">
              <div>
                <h3 className="font-semibold mb-1">
                  Train Your Website Bot
                </h3>
                <p className="text-sm text-neutral-500">
                  Add the website, runtime access, and business instructions the AI must follow.
                </p>
              </div>

              <div className="space-y-3">
                <div>
                  <Label htmlFor="website-url">Website URL</Label>
                  <Input
                    id="website-url"
                    placeholder="https://your-website.com"
                    className="mt-1.5"
                    value={websiteUrl}
                    onChange={(e) => setWebsiteUrl(e.target.value)}
                  />
                  <p className="mt-1 text-xs text-neutral-400">
                    Required for domain checks before the live widget can run.
                  </p>
                </div>

                <div>
                  <Label>Where should this widget work?</Label>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-2 mt-1.5">
                    {[
                      { value: "live", label: "Website", desc: "Live domain only" },
                      { value: "localhost", label: "Localhost", desc: "Development only" },
                      { value: "both", label: "Both", desc: "Live and localhost" },
                    ].map((option) => (
                      <button
                        key={option.value}
                        type="button"
                        onClick={() => setRuntimeMode(option.value as RuntimeMode)}
                        className={`text-left p-3 rounded-lg border transition-all ${
                          runtimeMode === option.value
                            ? "border-primary bg-primary/5 text-foreground"
                            : "border-border/50 hover:border-primary/30"
                        }`}
                      >
                        <div className="text-sm font-semibold">{option.label}</div>
                        <div className="text-xs text-neutral-400">{option.desc}</div>
                      </button>
                    ))}
                  </div>
                </div>

                <div>
                  <Label htmlFor="company-description">Company instructions</Label>
                  <Textarea
                    id="company-description"
                    value={companyDescription}
                    onChange={(e) => setCompanyDescription(e.target.value)}
                    placeholder="Describe your company, services, prices, policies, tone, support rules, and what the AI must not answer."
                    className="mt-1.5 min-h-[120px]"
                  />
                  <p className="mt-1 text-xs text-neutral-400">
                    Required. NexaBot follows this knowledge strictly.
                  </p>
                </div>

                <div
                  className="border-2 border-dashed border-border/50 rounded-xl p-6 text-center hover:border-primary/30 transition-all cursor-pointer"
                  onDragOver={(e) => e.preventDefault()}
                  onDrop={onDrop}
                  onClick={() => fileInputRef.current?.click()}
                >
                  <Upload className="w-6 h-6 text-neutral-400 mx-auto mb-2" />
                  <p className="text-sm font-medium mb-1">
                    Upload PDFs, DOCX, or TXT (optional)
                  </p>
                  <p className="text-xs text-neutral-400">Max 10MB per file</p>
                  <input
                    ref={fileInputRef}
                    type="file"
                    multiple
                    accept={ACCEPTED_MIMES.join(",")}
                    className="hidden"
                    onChange={(e) => onFilesSelected(e.target.files)}
                  />
                </div>

                {uploadedFiles.length > 0 && (
                  <div className="space-y-2">
                    {uploadedFiles.map((file) => (
                      <div
                        key={file.id}
                        className="flex items-center justify-between rounded-lg border border-border/40 px-3 py-2 text-sm"
                      >
                        <span className="truncate">{file.name}</span>
                        <span className="text-xs text-neutral-400">
                          {(file.size / 1024 / 1024).toFixed(2)} MB
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="flex gap-3 pt-2">
                <Button
                  className="flex-1 bg-primary text-white hover:bg-primary/90"
                  onClick={startTraining}
                  disabled={
                    training.inProgress ||
                    !websiteUrl.trim() ||
                    !companyDescription.trim()
                  }
                >
                  {training.inProgress ? "Saving..." : "Save and Continue"}
                </Button>
              </div>
              {training.inProgress && (
                <Progress value={training.progress} className="h-1" />
              )}
            </TabsContent>

            <TabsContent value="step-2" className="space-y-4">
              <h3 className="font-semibold">Connect Your Channels</h3>
              <p className="text-sm text-neutral-500">
                Choose where you want NexaBot to provide support.
              </p>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {[
                  {
                    icon: Globe,
                    label: "Website Chat",
                    desc: "Embed on your site with a script tag",
                    badge: "Recommended",
                    active: true,
                  },
                  {
                    icon: MessageSquare,
                    label: "WhatsApp",
                    desc: "Business API",
                    badge: "Coming Soon",
                    active: false,
                  },
                  {
                    icon: Smartphone,
                    label: "Messenger",
                    desc: "Facebook Pages",
                    badge: "Coming Soon",
                    active: false,
                  },
                ].map((channel) => (
                  <Card
                    key={channel.label}
                    className={`p-4 text-center border-2 cursor-pointer transition-all ${
                      selectedChannel === channel.label
                        ? "border-primary bg-primary/5"
                        : channel.active
                          ? "border-border/40 hover:border-primary/30"
                          : "border-border/20 opacity-50 cursor-not-allowed"
                    }`}
                    onClick={() => channel.active && chooseWebsiteChannel()}
                  >
                    <channel.icon className="w-6 h-6 text-primary mx-auto mb-2" />
                    <h4 className="font-semibold text-sm">{channel.label}</h4>
                    <p className="text-xs text-neutral-400">{channel.desc}</p>
                    <Badge
                      variant={channel.active ? "secondary" : "outline"}
                      className="mt-2 text-[10px]"
                    >
                      {channel.badge}
                    </Badge>
                  </Card>
                ))}
              </div>

              <div className="flex gap-3">
                <Button
                  variant="outline"
                  className="border-border"
                  onClick={() => setSetupStep(1)}
                >
                  Back
                </Button>
              </div>
            </TabsContent>

            <TabsContent value="step-3" className="space-y-4">
              <div>
                <h3 className="font-semibold">Customize and Launch</h3>
                <p className="text-sm text-neutral-500">
                  Adjust the widget, copy the snippet, then confirm the bot.
                </p>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                <div className="space-y-3">
                  <div>
                    <Label>Bot title</Label>
                    <Input
                      value={widgetTitle}
                      onChange={(e) => setWidgetTitle(e.target.value)}
                      className="mt-1.5"
                      placeholder="NexaBot"
                    />
                  </div>
                  <div>
                    <Label>Description</Label>
                    <Input
                      value={widgetSubtitle}
                      onChange={(e) => setWidgetSubtitle(e.target.value)}
                      className="mt-1.5"
                      placeholder="AI support assistant"
                    />
                  </div>
                  <div>
                    <Label>Logo URL</Label>
                    <Input
                      value={widgetLogoUrl}
                      onChange={(e) => setWidgetLogoUrl(e.target.value)}
                      className="mt-1.5"
                      placeholder="https://your-site.com/logo.png"
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <Label>Button text</Label>
                      <Input
                        value={widgetButtonLabel}
                        onChange={(e) => setWidgetButtonLabel(e.target.value)}
                        className="mt-1.5"
                      />
                    </div>
                    <div>
                      <Label>Accent color</Label>
                      <Input
                        type="color"
                        value={widgetColor}
                        onChange={(e) => setWidgetColor(e.target.value)}
                        className="mt-1.5 h-10 p-1"
                      />
                    </div>
                  </div>
                  <div>
                    <Label>Widget corner</Label>
                    <Select
                      value={widgetPosition}
                      onValueChange={(value) =>
                        setWidgetPosition(value as WidgetPosition)
                      }
                    >
                      <SelectTrigger className="mt-1.5">
                        <SelectValue placeholder="Choose corner" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="bottom-right">Bottom right</SelectItem>
                        <SelectItem value="bottom-left">Bottom left</SelectItem>
                        <SelectItem value="top-right">Top right</SelectItem>
                        <SelectItem value="top-left">Top left</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <div className="rounded-lg border border-border/40 bg-secondary/20 p-4">
                  <div className="text-sm font-semibold mb-3">Live preview</div>
                  <div className="relative h-[360px] rounded-lg bg-white border border-border/40 overflow-hidden">
                    <div
                      className={`absolute w-[280px] rounded-xl border border-border/40 bg-white shadow-xl overflow-hidden ${
                        widgetPosition.includes("top") ? "top-4" : "bottom-20"
                      } ${widgetPosition.includes("left") ? "left-4" : "right-4"}`}
                    >
                      <div className="flex items-center gap-2 p-3 border-b border-border/30">
                        {widgetLogoUrl ? (
                          <img
                            src={widgetLogoUrl}
                            alt=""
                            className="w-8 h-8 rounded-lg object-cover"
                          />
                        ) : (
                          <LogoIcon className="w-8 h-8" />
                        )}
                        <div className="min-w-0">
                          <div className="text-sm font-semibold truncate">
                            {widgetSettings.title}
                          </div>
                          <div className="text-xs text-neutral-400 truncate">
                            {widgetSettings.subtitle}
                          </div>
                        </div>
                      </div>
                      <div className="p-3 space-y-2 text-sm">
                        <div className="inline-block max-w-[85%] rounded-xl rounded-bl-sm bg-secondary px-3 py-2">
                          Hi. How can I help?
                        </div>
                        <div className="flex justify-end">
                          <div
                            className="inline-block max-w-[85%] rounded-xl rounded-br-sm px-3 py-2 text-white"
                            style={{ backgroundColor: widgetColor }}
                          >
                            Do you offer support?
                          </div>
                        </div>
                      </div>
                    </div>
                    <button
                      type="button"
                      className={`absolute h-12 px-4 rounded-xl text-sm font-semibold text-white shadow-lg ${
                        widgetPosition.includes("top") ? "top-4" : "bottom-4"
                      } ${widgetPosition.includes("left") ? "left-4" : "right-4"}`}
                      style={{ backgroundColor: widgetColor }}
                    >
                      {widgetSettings.buttonLabel}
                    </button>
                  </div>
                </div>
              </div>

              <div className="rounded-lg border border-border/40 bg-secondary/30 p-4 space-y-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="text-sm font-semibold flex items-center gap-2">
                      <Code2 className="w-4 h-4 text-primary" />
                      Install snippet
                    </div>
                    <p className="text-xs text-neutral-400">
                      Add this before the closing body tag on your website.
                    </p>
                  </div>
                  <Badge variant="secondary" className="bg-primary/10 text-primary">
                    {runtimeMode}
                  </Badge>
                </div>
                <pre className="overflow-x-auto rounded-lg bg-foreground text-background p-3 text-xs">
                  {embedCode || "Complete step 1 to generate your code snippet."}
                </pre>
                <div className="flex flex-col sm:flex-row gap-2">
                  <Button
                    variant="outline"
                    className="border-border"
                    onClick={() => {
                      if (!embedCode) return;
                      navigator.clipboard.writeText(embedCode);
                      setCopied(true);
                      setTimeout(() => setCopied(false), 1400);
                    }}
                    disabled={!embedCode}
                  >
                    <Copy className="w-4 h-4 mr-2" />
                    {copied ? "Copied" : "Copy Code"}
                  </Button>
                  <Button
                    className="flex-1 bg-primary text-white hover:bg-primary/90"
                    onClick={saveBot}
                    disabled={!embedCode || launching}
                  >
                    <Rocket className="w-4 h-4 mr-2" />
                    {launching ? "Saving..." : "Confirm Bot"}
                  </Button>
                </div>
              </div>

              <div className="flex gap-3">
                <Button
                  variant="outline"
                  className="border-border"
                  onClick={() => setSetupStep(2)}
                >
                  Back
                </Button>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );

  const renderBots = () => (
    <div className="space-y-6 animate-fade-up">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="space-y-1">
          <h2 className="text-2xl font-bold text-foreground">Bots</h2>
          <p className="text-sm text-neutral-500">
            Manage the chatbots you have confirmed from the setup wizard.
          </p>
        </div>
        <Button
          className="bg-primary text-white hover:bg-primary/90"
          onClick={() => {
            setSidebarView("overview");
            setSetupStep(1);
          }}
        >
          <Bot className="w-4 h-4 mr-2" />
          New Bot
        </Button>
      </div>

      {bots.length === 0 ? (
        <Card className="border-border/40">
          <CardContent className="p-8 text-center">
            <LogoIcon className="w-12 h-12 mx-auto mb-3" />
            <h3 className="font-semibold text-foreground">No bots yet</h3>
            <p className="text-sm text-neutral-500 mt-1">
              Finish the setup wizard and confirm your first website bot.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {bots.map((bot) => {
            const settings = bot.settings || {};
            const snippet = bot.public_api_key
              ? buildEmbedCode(bot.public_api_key, bot.bot_id)
              : "";
            return (
              <Card key={bot.bot_id} className="border-border/40">
                <CardContent className="p-5 space-y-4">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center gap-3 min-w-0">
                      {settings.logoUrl ? (
                        <img
                          src={settings.logoUrl}
                          alt=""
                          className="w-10 h-10 rounded-lg object-cover"
                        />
                      ) : (
                        <LogoIcon className="w-10 h-10 flex-shrink-0" />
                      )}
                      <div className="min-w-0">
                        <h3 className="font-semibold truncate">
                          {settings.title || "NexaBot"}
                        </h3>
                        <p className="text-xs text-neutral-400 truncate">
                          {bot.domain || "localhost"}
                        </p>
                      </div>
                    </div>
                    <Badge className="bg-primary/10 text-primary border-primary/20">
                      {bot.status || "active"}
                    </Badge>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div className="rounded-lg bg-secondary/40 p-3">
                      <div className="text-neutral-400 flex items-center gap-1">
                        <Monitor className="w-3.5 h-3.5" /> Runtime
                      </div>
                      <div className="font-medium mt-1">
                        {settings.runtimeMode || bot["runtime_mode"] || "live"}
                      </div>
                    </div>
                    <div className="rounded-lg bg-secondary/40 p-3">
                      <div className="text-neutral-400 flex items-center gap-1">
                        <KeyRound className="w-3.5 h-3.5" /> Key
                      </div>
                      <div className="font-medium mt-1 truncate">
                        {bot.public_api_key ? `${bot.public_api_key.slice(0, 10)}...` : "Missing"}
                      </div>
                    </div>
                  </div>

                  {snippet && (
                    <div className="space-y-2">
                      <pre className="overflow-x-auto rounded-lg bg-foreground text-background p-3 text-xs">
                        {snippet}
                      </pre>
                      <Button
                        variant="outline"
                        className="w-full border-border"
                        onClick={() => navigator.clipboard.writeText(snippet)}
                      >
                        <Copy className="w-4 h-4 mr-2" />
                        Copy Snippet
                      </Button>
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );

  const renderFeatures = () => (
    <div className="space-y-6 animate-fade-up">
      <div className="space-y-1">
        <h2 className="text-2xl font-bold text-foreground">
          Platform Features
        </h2>
        <p className="text-sm text-neutral-500">
          All the tools you need to power your customer support.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {[
          {
            icon: MessageSquare,
            title: "AI Chat",
            desc: "Natural conversations with instant AI responses.",
            color: "text-primary",
            bg: "bg-primary/10",
          },
          {
            icon: GraduationCap,
            title: "Bot Training",
            desc: "Train on your data for personalized responses.",
            color: "text-emerald-600",
            bg: "bg-emerald-500/10",
          },
          {
            icon: Globe,
            title: "Omnichannel",
            desc: "Deploy on website, WhatsApp, Messenger, Slack.",
            color: "text-blue-600",
            bg: "bg-blue-500/10",
          },
          {
            icon: FileText,
            title: "Document Analysis",
            desc: "Process PDFs, DOCX, and TXT files.",
            color: "text-violet-600",
            bg: "bg-violet-500/10",
          },
          {
            icon: Shield,
            title: "Security",
            desc: "End-to-end encryption and GDPR compliance.",
            color: "text-amber-600",
            bg: "bg-amber-500/10",
          },
          {
            icon: BarChart3,
            title: "Analytics",
            desc: "Track conversations, leads, and insights.",
            color: "text-rose-600",
            bg: "bg-rose-500/10",
          },
        ].map((feat, i) => (
          <Card
            key={i}
            className="border-border/40 hover:border-border/70 transition-all"
          >
            <CardContent className="p-5">
              <div
                className={`w-9 h-9 rounded-xl ${feat.bg} flex items-center justify-center mb-3`}
              >
                <feat.icon className={`w-4.5 h-4.5 ${feat.color}`} />
              </div>
              <h3 className="font-semibold text-sm mb-1">{feat.title}</h3>
              <p className="text-xs text-neutral-500">{feat.desc}</p>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );

  const renderSubscription = () => {
    const createdAt = (user as any)?.created_at ? new Date((user as any).created_at) : null;
    const trialEnd = createdAt ? new Date(createdAt) : null;
    if (trialEnd) trialEnd.setMonth(trialEnd.getMonth() + 3);

    const now = Date.now();
    const msLeft = trialEnd ? trialEnd.getTime() - now : null;
    const daysLeft = msLeft !== null ? Math.max(0, Math.ceil(msLeft / (1000 * 60 * 60 * 24))) : null;

    const included = [
      "Unlimited conversations",
      "Website chat widget",
      "WhatsApp integration",
      "Messenger integration",
      "Slack & Discord support",
      "Lead capture & notifications",
      "Custom AI training",
      "Analytics dashboard",
      "Email support",
    ];

    return (
      <div className="space-y-6 animate-fade-up max-w-3xl">
        <div className="space-y-1">
          <h2 className="text-2xl font-bold text-foreground">Subscription</h2>
          <p className="text-sm text-neutral-500">
            View your current plan and remaining access.
          </p>
        </div>

        <Card className="border-primary/15 bg-gradient-to-br from-primary/5 to-cyan-400/5">
          <CardHeader>
            <CardTitle className="text-base flex items-center justify-between">
              <span>Beta Access Plan</span>
              <Badge className="bg-primary/10 text-primary border-primary/20">
                Active
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="p-4 rounded-xl bg-background border border-border/40">
                <div className="text-xs text-neutral-400">Price</div>
                <div className="text-lg font-semibold text-foreground">Free</div>
                <div className="text-xs text-neutral-400">during beta</div>
              </div>
              <div className="p-4 rounded-xl bg-background border border-border/40">
                <div className="text-xs text-neutral-400">Trial</div>
                <div className="text-lg font-semibold text-foreground">
                  3 months
                </div>
                <div className="text-xs text-neutral-400">beta access</div>
              </div>
              <div className="p-4 rounded-xl bg-background border border-border/40">
                <div className="text-xs text-neutral-400">Time Left</div>
                <div className="text-lg font-semibold text-foreground">
                  {daysLeft === null ? "—" : `${daysLeft} days`}
                </div>
                <div className="text-xs text-neutral-400">
                  {trialEnd ? `Until ${trialEnd.toLocaleDateString()}` : "—"}
                </div>
              </div>
            </div>

            <div className="p-5 rounded-xl bg-background border border-border/40">
              <div className="text-sm font-semibold text-foreground mb-3">
                Everything included
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-y-2 gap-x-4">
                {included.map((f) => (
                  <div key={f} className="flex items-center gap-2 text-sm text-neutral-600">
                    <Check className="w-4 h-4 text-primary flex-shrink-0" />
                    <span>{f}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="flex items-center justify-between gap-3">
              <div className="text-xs text-neutral-400">
                Beta users automatically get a 3-month free trial.
              </div>
              <Button variant="outline" className="border-border" disabled>
                Manage Subscription
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  };

  const renderSettings = () => (
    <div className="space-y-6 animate-fade-up max-w-2xl">
      <div className="space-y-1">
        <h2 className="text-2xl font-bold text-foreground">Settings</h2>
        <p className="text-sm text-neutral-500">
          Configure your NexaBot preferences.
        </p>
      </div>

      <Card className="border-border/40">
        <CardHeader>
          <CardTitle className="text-base">General Settings</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label>Bot Name</Label>
            <Input placeholder="NexaBot Assistant" className="mt-1.5" />
          </div>
          <div>
            <Label>Welcome Message</Label>
            <Input
              placeholder="Hi! How can I help you today?"
              className="mt-1.5"
            />
          </div>
          <div>
            <Label>Default Channel</Label>
            <div className="grid grid-cols-3 gap-2 mt-1.5">
              {["Website", "WhatsApp", "Messenger"].map((ch) => (
                <Button
                  key={ch}
                  variant="outline"
                  className="border-border text-sm"
                >
                  {ch}
                </Button>
              ))}
            </div>
          </div>
          <Button className="bg-primary text-white hover:bg-primary/90">
            Save Settings
          </Button>
        </CardContent>
      </Card>
    </div>
  );

  const renderProfile = () => (
    <div className="space-y-6 animate-fade-up max-w-2xl">
      <div className="space-y-1">
        <h2 className="text-2xl font-bold text-foreground">Profile</h2>
        <p className="text-sm text-neutral-500">Manage your account details.</p>
      </div>

      <Card className="border-border/40">
        <CardContent className="p-6 space-y-4">
          <div className="flex items-center gap-4 pb-4 border-b border-border/30">
            <div className="w-14 h-14 rounded-2xl gradient-bg flex items-center justify-center text-white font-bold text-xl">
              {businessName.charAt(0)}
            </div>
            <div>
              <h3 className="font-semibold">{businessName}</h3>
              <p className="text-sm text-neutral-400">
                {user?.email || "user@nexabot.ai"}
              </p>
            </div>
          </div>

          <div>
            <Label>Business Name</Label>
            <Input value={businessName} className="mt-1.5" />
          </div>
          <div>
            <Label>Email</Label>
            <Input value={user?.email || ""} className="mt-1.5" disabled />
          </div>
          <div className="flex items-center justify-between pt-2">
            <Badge
              variant="secondary"
              className="bg-primary/10 text-primary border-primary/20"
            >
              Beta Access
            </Badge>
            <Button
              variant="outline"
              className="border-border text-sm"
              onClick={handleLogout}
            >
              <LogOut className="w-4 h-4 mr-2" /> Sign Out
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );

  return (
    <div className="min-h-screen bg-sidebar-background flex">
      {/* Desktop Sidebar */}
      <div className="hidden lg:flex h-screen sticky top-0">
        {renderSidebar()}
      </div>

      {/* Mobile Header */}
      <div className="lg:hidden fixed top-0 left-0 right-0 z-50 bg-white border-b border-border/40 px-4 py-3 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <button
            onClick={() => setMobileSidebarOpen(true)}
            className="p-1.5 rounded-lg hover:bg-secondary"
          >
            <Menu className="w-5 h-5" />
          </button>
          <LogoIcon className="w-7 h-7" />
          <LogoText className="text-sm" />
        </div>
        <Badge
          variant="secondary"
          className="bg-primary/10 text-primary border-primary/20 text-[10px]"
        >
          Beta
        </Badge>
      </div>

      {/* Mobile Sidebar Overlay */}
      {mobileSidebarOpen && (
        <div className="lg:hidden fixed inset-0 z-50 flex">
          <div
            className="absolute inset-0 bg-black/30"
            onClick={() => setMobileSidebarOpen(false)}
          />
          <div className="relative w-64 bg-white border-r border-border/40 shadow-xl animate-slide-in">
            <div className="flex items-center justify-between p-4 border-b border-border/30">
              <div className="flex items-center gap-2.5">
                <LogoIcon className="w-8 h-8" />
                <LogoText className="text-base" />
              </div>
              <button
                onClick={() => setMobileSidebarOpen(false)}
                className="p-1.5 rounded-lg hover:bg-secondary"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="py-4 space-y-1 px-3">
              {sidebarItems.map((item) => (
                <button
                  key={item.view}
                  onClick={() => {
                    setSidebarView(item.view);
                    setMobileSidebarOpen(false);
                  }}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                    sidebarView === item.view
                      ? "bg-primary/10 text-primary"
                      : "text-neutral-600 hover:bg-secondary"
                  }`}
                >
                  <item.icon className="w-5 h-5" />
                  {item.label}
                </button>
              ))}
            </div>
            <div className="p-3 border-t border-border/30">
              <button
                onClick={handleLogout}
                className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm text-neutral-500 hover:bg-secondary hover:text-foreground transition-all"
              >
                <LogOut className="w-5 h-5" /> Sign Out
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Main Content */}
      <div className="flex-1 min-h-screen overflow-y-auto">
        <div className="lg:pt-0 pt-16">
          <div className="container mx-auto px-6 py-8 max-w-6xl">
            {renderContent()}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
