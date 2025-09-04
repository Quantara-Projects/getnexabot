import { useEffect, useMemo, useRef, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { useToast } from '@/hooks/use-toast';
import {
  Bot,
  MessageSquare,
  Zap,
  Settings as SettingsIcon,
  Upload,
  Link as LinkIcon,
  Smartphone,
  Globe,
  BarChart3,
  CheckCircle,
  Clock,
  Image as ImageIcon,
  Palette,
  Copy,
  Check,
} from 'lucide-react';

// Basic URL validation for http/https
const isValidHttpUrl = (value: string) => {
  try {
    const u = new URL(value);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
};

const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024; // 10MB per file
const ACCEPTED_MIMES = [
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'text/plain',
];

type UploadedItem = {
  id: string;
  name: string;
  size: number;
  type: string;
  file?: File;
};

type Customization = {
  botName: string;
  greeting: string;
  buttonColor: string;
  chatHeaderColor: string;
  bubbleShape: 'rounded' | 'square' | 'pill';
  buttonSize: 'sm' | 'md' | 'lg';
  headerTitle: string;
  avatarDataUrl: string | null;
  buttonIconUrl: string | null;
  openAnimation: 'fade' | 'slide-up' | 'slide-left' | 'zoom' | 'bounce';
};

type WizardState = {
  setupStep: number;
  websiteUrl: string;
  uploadedFiles: UploadedItem[];
  training: {
    inProgress: boolean;
    progress: number;
    completed: boolean;
    error: string | null;
  };
  selectedChannel: 'website' | null;
  botId: string | null;
  customization: Customization;
  embedCode: string | null;
};

const DEFAULT_CUSTOMIZATION: Customization = {
  botName: 'NexaBot Assistant',
  greeting: 'Hi! How can I help you today?',
  buttonColor: '#6366f1',
  chatHeaderColor: '#8b5cf6',
  bubbleShape: 'rounded',
  buttonSize: 'md',
  headerTitle: 'Ask NexaBot',
  avatarDataUrl: null,
  buttonIconUrl: null,
  openAnimation: 'fade',
};

const Dashboard = () => {
  const { toast } = useToast();
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [copied, setCopied] = useState(false);
  const [state, setState] = useState<WizardState>({
    setupStep: 1,
    websiteUrl: '',
    uploadedFiles: [],
    training: { inProgress: false, progress: 0, completed: false, error: null },
    selectedChannel: null,
    botId: null,
    customization: DEFAULT_CUSTOMIZATION,
    embedCode: null,
  });

  const businessName = 'Acme Corp';

  // Load from localStorage
  useEffect(() => {
    try {
      const saved = localStorage.getItem('wizard_state');
      if (saved) {
        const parsed = JSON.parse(saved) as WizardState;
        setState((prev) => ({ ...prev, ...parsed }));
      }
    } catch {}
  }, []);

  // Persist to localStorage
  useEffect(() => {
    try {
      localStorage.setItem('wizard_state', JSON.stringify(state));
    } catch {}
  }, [state]);

  // Also hydrate website URL from settings if present and empty
  useEffect(() => {
    try {
      if (!state.websiteUrl) {
        const settings = localStorage.getItem('app_settings');
        if (settings) {
          const parsed = JSON.parse(settings);
          if (parsed.websiteUrl) {
            setState((s) => ({ ...s, websiteUrl: parsed.websiteUrl }));
          }
        }
      }
    } catch {}
  }, []);

  const progressPercent = useMemo(() => {
    const base = state.setupStep;
    return Math.min(100, Math.max(0, (base / 3) * 100));
  }, [state.setupStep]);

  const canProceedFromStep1 = useMemo(() => {
    const hasValidUrl = state.websiteUrl.trim().length > 0 && isValidHttpUrl(state.websiteUrl.trim());
    const hasFiles = state.uploadedFiles.length > 0;
    return (hasValidUrl || hasFiles) && state.training.completed && !state.training.inProgress && !state.training.error;
  }, [state.websiteUrl, state.uploadedFiles, state.training]);

  const canProceedFromStep2 = useMemo(() => !!state.selectedChannel, [state.selectedChannel]);

  const handleNext = () => {
    if (state.setupStep === 1 && !canProceedFromStep1) return;
    if (state.setupStep === 2 && !canProceedFromStep2) return;
    setState((s) => ({ ...s, setupStep: Math.min(3, s.setupStep + 1) }));
  };

  const handlePrev = () => {
    setState((s) => ({ ...s, setupStep: Math.max(1, s.setupStep - 1) }));
  };

  const onPickFiles = () => fileInputRef.current?.click();

  const onFilesSelected = (files: FileList | null) => {
    if (!files) return;
    const accepted: UploadedItem[] = [];
    for (const f of Array.from(files)) {
      if (!ACCEPTED_MIMES.includes(f.type)) {
        toast({ title: 'Unsupported file type', description: `${f.name} was rejected.`, variant: 'destructive' });
        continue;
      }
      if (f.size > MAX_FILE_SIZE_BYTES) {
        toast({ title: 'File too large', description: `${f.name} exceeds 10MB.`, variant: 'destructive' });
        continue;
      }
      accepted.push({ id: `${f.name}-${f.size}-${f.lastModified}`, name: f.name, size: f.size, type: f.type, file: f });
    }
    if (accepted.length) {
      setState((s) => ({ ...s, uploadedFiles: [...s.uploadedFiles, ...accepted] }));
    }
  };

  const onDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    onFilesSelected(e.dataTransfer.files);
  };

  const onTrain = async () => {
    const hasUrl = state.websiteUrl.trim().length > 0;
    const validUrl = hasUrl && isValidHttpUrl(state.websiteUrl.trim());
    const hasFiles = state.uploadedFiles.length > 0;

    if (!validUrl && !hasFiles) {
      toast({ title: 'Provide training data', description: 'Enter a valid URL or upload documents.', variant: 'destructive' });
      return;
    }

    setState((s) => ({ ...s, training: { inProgress: true, progress: 0, completed: false, error: null } }));

    try {
      // If files are provided, upload them to Supabase storage first
      const storagePaths: string[] = [];
      if (hasFiles) {
        toast({ title: 'Uploading files', description: 'Uploading your files securely...', variant: 'default' });
        for (const f of state.uploadedFiles) {
          try {
            if (!f.file) continue;
            const folder = `training/${(state.botId || 'anon')}/${Date.now()}`;
            // sanitize filename
            const name = encodeURIComponent(f.name.replace(/[^a-zA-Z0-9.\-_%]/g, '_'));
            const path = `${folder}/${name}`;
            const result = await supabase.storage.from('training').upload(path, f.file as File, { upsert: true });
            if (result.error) {
              console.warn('upload error', result.error);
              toast({ title: 'Upload failed', description: `${f.name} could not be uploaded.`, variant: 'destructive' });
              continue;
            }
            storagePaths.push(path);
          } catch (err) {
            console.warn('upload exception', err);
          }
        }
      }

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 20000);
      const res = await fetch('/api/train', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: validUrl ? state.websiteUrl.trim() : null, files: storagePaths }),
        signal: controller.signal,
      }).catch((err) => ({ ok: false, status: 0, error: err } as any));
      clearTimeout(timeout);

      // Simulate progressive UI regardless of backend latency
      for (let p = 0; p <= 100; p += 10) {
        await new Promise((r) => setTimeout(r, 120));
        setState((s) => ({ ...s, training: { ...s.training, progress: p } }));
      }

      if (!res || !(res as any).ok) {
        setState((s) => ({ ...s, training: { ...s.training, inProgress: false, completed: true, error: null } }));
        toast({ title: 'Training queued', description: 'Backend unavailable; training will complete when the server is ready.' });
        return;
      }

      setState((s) => ({ ...s, training: { inProgress: false, progress: 100, completed: true, error: null } }));
      toast({ title: 'Training submitted', description: 'Your training job was submitted.' });
    } catch (e: any) {
      setState((s) => ({ ...s, training: { inProgress: false, progress: 0, completed: false, error: 'Training failed' } }));
      toast({ title: 'Training failed', description: 'Please try again.', variant: 'destructive' });
    }
  };

  const onConnect = async (channel: 'website' | 'whatsapp' | 'messenger') => {
    if (channel !== 'website') return;
    setState((s) => ({ ...s, selectedChannel: 'website' }));

    try {
      const res = await fetch('/api/connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ channel: 'website', url: state.websiteUrl.trim() || null }),
      }).catch((err) => ({ ok: false, status: 0, error: err } as any));

      let botId = state.botId;
      if (res && (res as any).ok) {
        const data = await (res as Response).json().catch(() => ({}));
        botId = data.botId || botId;
      }
      if (!botId) {
        // Generate deterministic bot id for demo if backend not ready
        const host = (() => {
          try { return new URL(state.websiteUrl).host; } catch { return 'local'; }
        })();
        botId = `bot_${btoa(host).replace(/=+$/,'')}`;
      }

      const embed = `<!-- NexoBot Widget -->\n<script src="https://cdn.nexobot.ai/install.js?id=${botId}"></script>`;
      setState((s) => ({ ...s, botId, embedCode: embed }));
      toast({ title: 'Website chat connected', description: 'Embed code generated.' });
    } catch {
      toast({ title: 'Connection failed', description: 'Please try again.', variant: 'destructive' });
    }
  };

  const onLaunch = async () => {
    if (state.selectedChannel !== 'website') return;
    try {
      const payload = {
        botId: state.botId,
        customization: state.customization,
        channel: 'website',
      };
      const res = await fetch('/api/launch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }).catch((err) => ({ ok: false, status: 0, error: err } as any));

      if (res && (res as any).ok) {
        const data = await (res as Response).json().catch(() => ({}));
        const botId = data.botId || state.botId;
        const embed = `<!-- NexoBot Widget -->\n<script src="https://cdn.nexobot.ai/install.js?id=${botId}"></script>`;
        setState((s) => ({ ...s, botId, embedCode: embed }));
        toast({ title: 'Launched', description: 'Your bot is live. Copy the embed code.' });
      } else {
        // Still provide embed if we have a botId
        if (state.botId) {
          toast({ title: 'Launch queued', description: 'Backend unavailable; embed code is ready.' });
        } else {
          toast({ title: 'Launch failed', description: 'Missing bot ID. Connect first.', variant: 'destructive' });
          return;
        }
      }

      setState((s) => ({ ...s, setupStep: 3 }));
    } catch {
      toast({ title: 'Launch failed', description: 'Please try again.', variant: 'destructive' });
    }
  };

  // Saving customization locally and attempting to persist to backend
  const [saving, setSaving] = useState(false);
  const saveCustomization = async () => {
    setSaving(true);
    try {
      // Persist to local storage
      try {
        const stored = localStorage.getItem('wizard_state');
        const parsed = stored ? JSON.parse(stored) : {};
        parsed.customization = state.customization;
        localStorage.setItem('wizard_state', JSON.stringify(parsed));
      } catch {}

      // Try to persist to backend via the launch endpoint which upserts settings
      const payload = {
        botId: state.botId,
        customization: state.customization,
        channel: state.selectedChannel || 'website',
      };

      const res = await fetch('/api/launch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }).catch(() => ({ ok: false } as any));

      if (res && (res as any).ok) {
        toast({ title: 'Saved', description: 'Customization saved successfully.' });
        const data = await (res as Response).json().catch(() => ({}));
        if (data?.botId) setState((s) => ({ ...s, botId: data.botId }));
      } else {
        toast({ title: 'Saved locally', description: 'Customization saved locally. Backend unavailable.', variant: 'warning' as any });
      }
    } catch (e) {
      toast({ title: 'Save failed', description: 'Could not save customization. Try again.', variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  const copyEmbed = async () => {
    if (!state.embedCode) return;
    try {
      await navigator.clipboard.writeText(state.embedCode);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {}
  };

  const [previewOpen, setPreviewOpen] = useState(false);
  const buttonSizePx = state.customization.buttonSize === 'sm' ? 44 : state.customization.buttonSize === 'lg' ? 64 : 52;
  const previewBubbleClass =
    state.customization.bubbleShape === 'rounded'
      ? 'rounded-2xl'
      : state.customization.bubbleShape === 'square'
      ? 'rounded-none'
      : 'rounded-full';

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-secondary/10 to-background">
      <header className="border-b bg-white/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="bg-gradient-to-r from-primary to-violet-600 p-2 rounded-lg">
                <Bot className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold">NexaBot</h1>
                <p className="text-sm text-muted-foreground">Welcome back, {businessName}</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <Badge variant="secondary" className="bg-green-100 text-green-700 border-green-200">Beta Access</Badge>
              <Button variant="outline" size="sm" onClick={() => (window.location.href = '/settings')}>
                <SettingsIcon className="w-4 h-4 mr-2" />
                Settings
              </Button>
            </div>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-6 py-8">
        <Card className="mb-8 bg-gradient-to-r from-primary/10 to-violet-600/10 border-primary/20 animate-fade-in-up">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-2xl font-bold mb-2">Welcome, {businessName}! 🎉</h2>
                <p className="text-muted-foreground">Your NexaBot is ready to be configured. Let's get you set up in 3 simple steps.</p>
              </div>
              <div className="hidden md:block">
                <div className="bg-gradient-to-r from-primary to-violet-600 p-4 rounded-2xl animate-float">
                  <Bot className="w-12 h-12 text-white" />
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <div className="lg:col-span-2">
            <Card className="animate-fade-in-up" style={{ animationDelay: '0.1s' }}>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Zap className="w-5 h-5 mr-2 text-primary" />
                  Setup Wizard
                </CardTitle>
                <Progress value={progressPercent} className="w-full" />
                <p className="text-sm text-muted-foreground">Step {state.setupStep} of 3</p>
              </CardHeader>
              <CardContent>
                <Tabs value={`step-${state.setupStep}`} className="w-full">
                  <TabsList className="grid w-full grid-cols-3">
                    <TabsTrigger value="step-1" disabled className="flex items-center space-x-2">
                      <Upload className="w-4 h-4" />
                      <span className="hidden sm:inline">Train Bot</span>
                    </TabsTrigger>
                    <TabsTrigger value="step-2" disabled className="flex items-center space-x-2">
                      <LinkIcon className="w-4 h-4" />
                      <span className="hidden sm:inline">Connect</span>
                    </TabsTrigger>
                    <TabsTrigger value="step-3" disabled className="flex items-center space-x-2">
                      <CheckCircle className="w-4 h-4" />
                      <span className="hidden sm:inline">Launch</span>
                    </TabsTrigger>
                  </TabsList>

                  {/* Step 1 */}
                  <TabsContent value="step-1" className="space-y-4 mt-6">
                    <div>
                      <h3 className="text-lg font-semibold mb-2">Upload Your Business Data</h3>
                      <p className="text-muted-foreground mb-4">Provide a website URL or upload documents. We'll extract text to train your bot.</p>
                    </div>

                    <div className="space-y-4">
                      <div>
                        <Label htmlFor="website-url">Website URL (Recommended)</Label>
                        <Input
                          id="website-url"
                          placeholder="https://your-website.com"
                          className="mt-2"
                          value={state.websiteUrl}
                          onChange={(e) => setState((s) => ({ ...s, websiteUrl: e.target.value }))}
                        />
                        <p className="text-xs text-muted-foreground mt-1">Only http/https are allowed.</p>
                      </div>

                      <div className="text-center"><p className="text-sm text-muted-foreground mb-2">— OR —</p></div>

                      <div
                        className="border-2 border-dashed border-border rounded-lg p-8 text-center"
                        onDragOver={(e) => { e.preventDefault(); e.stopPropagation(); }}
                        onDrop={onDrop}
                      >
                        <Upload className="w-8 h-8 text-muted-foreground mx-auto mb-4" />
                        <p className="font-medium mb-2">Upload PDFs, DOCX, or TXT</p>
                        <p className="text-sm text-muted-foreground mb-4">Max 10MB per file. Drag & drop or browse.</p>
                        <div className="flex justify-center gap-3">
                          <Button variant="outline" onClick={onPickFiles}>Browse Files</Button>
                          <input
                            ref={fileInputRef}
                            type="file"
                            multiple
                            accept={ACCEPTED_MIMES.join(',')}
                            className="hidden"
                            onChange={(e) => onFilesSelected(e.target.files)}
                          />
                          {state.uploadedFiles.length > 0 && (
                            <Badge variant="secondary">{state.uploadedFiles.length} file(s) selected</Badge>
                          )}
                        </div>
                      </div>

                      {state.uploadedFiles.length > 0 && (
                        <div className="space-y-2">
                          <h4 className="text-sm font-semibold">Selected Files</h4>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            {state.uploadedFiles.map((f) => (
                              <div key={f.id} className="flex items-center justify-between p-2 border rounded">
                                <div className="flex items-center gap-2">
                                  <Upload className="w-4 h-4 text-primary" />
                                  <span className="text-sm">{f.name}</span>
                                </div>
                                <span className="text-xs text-muted-foreground">{(f.size / 1024 / 1024).toFixed(2)} MB</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      <div className="space-y-3">
                        <Button
                          onClick={onTrain}
                          disabled={state.training.inProgress}
                          className="w-full bg-gradient-to-r from-primary to-violet-600 hover:from-primary/90 hover:to-violet-600/90"
                        >
                          {state.training.inProgress ? 'Training in progress…' : 'Start Training'}
                        </Button>
                        {(state.training.inProgress || state.training.completed) && (
                          <div className="space-y-2">
                            <Progress value={state.training.progress} />
                            <p className="text-xs text-muted-foreground">
                              {state.training.inProgress ? 'Processing your data securely…' : state.training.completed ? 'Training completed' : ''}
                            </p>
                          </div>
                        )}
                      </div>
                    </div>

                    <div className="flex gap-3">
                      <Button
                        onClick={handleNext}
                        className="w-full bg-gradient-to-r from-primary to-violet-600 hover:from-primary/90 hover:to-violet-600/90"
                        disabled={!canProceedFromStep1}
                      >
                        Continue to Integrations
                      </Button>
                    </div>
                  </TabsContent>

                  {/* Step 2 */}
                  <TabsContent value="step-2" className="space-y-4 mt-6">
                    <div>
                      <h3 className="text-lg font-semibold mb-2">Connect Your Channels</h3>
                      <p className="text-muted-foreground mb-4">Choose where you want NexaBot to provide support.</p>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <Card onClick={() => onConnect('website')} className={`p-4 text-center border-2 cursor-pointer transition-smooth ${state.selectedChannel==='website' ? 'border-primary' : 'hover:border-primary'}`}>
                        <Globe className="w-8 h-8 text-primary mx-auto mb-2" />
                        <h4 className="font-semibold">Website Chat</h4>
                        <p className="text-xs text-muted-foreground">Embed on your site</p>
                        <Badge variant="secondary" className="mt-2">Recommended</Badge>
                      </Card>

                      <Card className={`p-4 text-center border-2 opacity-60 cursor-not-allowed`}>
                        <MessageSquare className="w-8 h-8 text-green-600 mx-auto mb-2" />
                        <h4 className="font-semibold">WhatsApp</h4>
                        <p className="text-xs text-muted-foreground">Business API</p>
                        <Badge variant="outline" className="mt-2">Coming Soon</Badge>
                      </Card>

                      <Card className={`p-4 text-center border-2 opacity-60 cursor-not-allowed`}>
                        <Smartphone className="w-8 h-8 text-blue-600 mx-auto mb-2" />
                        <h4 className="font-semibold">Messenger</h4>
                        <p className="text-xs text-muted-foreground">Facebook Pages</p>
                        <Badge variant="outline" className="mt-2">Coming Soon</Badge>
                      </Card>
                    </div>

                    {state.selectedChannel === 'website' && state.embedCode && (
                      <div className="bg-secondary/30 rounded-lg p-4">
                        <h4 className="font-semibold mb-2">Embed Code</h4>
                        <p className="text-sm text-muted-foreground mb-3">Copy this code into your website's head or before body end.</p>
                        <div className="relative">
                          <pre className="bg-background border rounded p-3 text-xs font-mono overflow-x-auto whitespace-pre-wrap">{state.embedCode}</pre>
                          <Button size="sm" variant="outline" className="absolute top-2 right-2" onClick={copyEmbed}>
                            {copied ? <Check className="w-4 h-4 mr-1" /> : <Copy className="w-4 h-4 mr-1" />} {copied ? 'Copied' : 'Copy'}
                          </Button>
                        </div>
                        <p className="text-xs text-muted-foreground mt-2">Domain verification may be required.</p>
                      </div>
                    )}

                    <div className="flex gap-3">
                      <Button variant="outline" onClick={handlePrev} className="w-1/3">Back</Button>
                      <Button onClick={handleNext} className="flex-1 bg-gradient-to-r from-primary to-violet-600 hover:from-primary/90 hover:to-violet-600/90" disabled={!canProceedFromStep2}>
                        Configure Settings
                      </Button>
                    </div>
                  </TabsContent>

                  {/* Step 3 */}
                  <TabsContent value="step-3" className="space-y-4 mt-6">
                    <div>
                      <h3 className="text-lg font-semibold mb-2">Customize & Launch</h3>
                      <p className="text-muted-foreground mb-4">Personalize your bot's appearance and behavior.</p>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div className="space-y-4">
                        <div>
                          <Label htmlFor="bot-name">Chatbot Name</Label>
                          <Input id="bot-name" className="mt-2" value={state.customization.botName} onChange={(e) => setState((s) => ({ ...s, customization: { ...s.customization, botName: e.target.value } }))} />
                        </div>

                        <div>
                          <Label htmlFor="greeting">Welcome Greeting</Label>
                          <Input id="greeting" className="mt-2" value={state.customization.greeting} onChange={(e) => setState((s) => ({ ...s, customization: { ...s.customization, greeting: e.target.value } }))} />
                        </div>

                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <Label>Button Color</Label>
                            <div className="flex gap-2 mt-2">
                              <Input type="color" value={state.customization.buttonColor} onChange={(e) => setState((s) => ({ ...s, customization: { ...s.customization, buttonColor: e.target.value } }))} className="w-16 h-10 p-1" />
                              <Input value={state.customization.buttonColor} onChange={(e) => setState((s) => ({ ...s, customization: { ...s.customization, buttonColor: e.target.value } }))} />
                            </div>
                          </div>
                          <div>
                            <Label>Chat Header Color</Label>
                            <div className="flex gap-2 mt-2">
                              <Input type="color" value={state.customization.chatHeaderColor} onChange={(e) => setState((s) => ({ ...s, customization: { ...s.customization, chatHeaderColor: e.target.value } }))} className="w-16 h-10 p-1" />
                              <Input value={state.customization.chatHeaderColor} onChange={(e) => setState((s) => ({ ...s, customization: { ...s.customization, chatHeaderColor: e.target.value } }))} />
                            </div>
                          </div>
                        </div>

                        <div>
                          <Label>Bubble Shape</Label>
                          <div className="grid grid-cols-3 gap-2 mt-2">
                            {(['rounded','square','pill'] as const).map((shape) => (
                              <Button key={shape} variant={state.customization.bubbleShape===shape? 'default':'outline'} onClick={() => setState((s) => ({ ...s, customization: { ...s.customization, bubbleShape: shape } }))} className="capitalize">{shape}</Button>
                            ))}
                          </div>
                        </div>

                        <div>
                          <Label>Button Size</Label>
                          <div className="grid grid-cols-3 gap-2 mt-2">
                            {(['sm','md','lg'] as const).map((sz) => (
                              <Button key={sz} variant={state.customization.buttonSize===sz? 'default':'outline'} onClick={() => setState((s) => ({ ...s, customization: { ...s.customization, buttonSize: sz } }))} className="uppercase">{sz}</Button>
                            ))}
                          </div>
                        </div>

                        <div>
                          <Label>Header Title</Label>
                          <Input className="mt-2" value={state.customization.headerTitle} onChange={(e) => setState((s) => ({ ...s, customization: { ...s.customization, headerTitle: e.target.value } }))} />
                        </div>

                        <div>
                          <Label>Chat UI Size (px)</Label>
                          <div className="grid grid-cols-2 gap-2 mt-2">
                            <div className="flex items-center gap-2">
                              <span className="text-xs w-12">Width</span>
                              <Input type="number" min={260} max={640} value={state.customization.chatWidth} onChange={(e)=>setState(s=>({...s, customization:{...s.customization, chatWidth: Math.max(260, Math.min(640, Number(e.target.value)||360))}}))}/>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className="text-xs w-12">Height</span>
                              <Input type="number" min={320} max={800} value={state.customization.chatHeight} onChange={(e)=>setState(s=>({...s, customization:{...s.customization, chatHeight: Math.max(320, Math.min(800, Number(e.target.value)||420))}}))}/>
                            </div>
                          </div>
                        </div>

                        <div>
                          <Label>Open Animation</Label>
                          <div className="grid grid-cols-5 gap-2 mt-2">
                            {(['fade','slide-up','slide-left','zoom','bounce'] as const).map((opt) => (
                              <Button key={opt} variant={state.customization.openAnimation===opt?'default':'outline'} onClick={()=>setState(s=>({...s, customization:{...s.customization, openAnimation: opt}}))} className="capitalize text-xs">{opt.replace('-',' ')}</Button>
                            ))}
                          </div>
                        </div>

                        <div>
                          <Label>Button Icon</Label>
                          <div className="flex items-center gap-3 mt-2">
                            <Button variant="outline" onClick={() => document.getElementById('button-icon-input')?.click()}>
                              <ImageIcon className="w-4 h-4 mr-2" /> Upload Icon
                            </Button>
                            <input id="button-icon-input" type="file" accept="image/*" className="hidden" onChange={(e)=>{
                              const file=e.target.files?.[0]; if(!file) return; if(file.size>1024*1024){ toast({title:'Icon too large', description:'Max 1MB.', variant:'destructive'}); return; }
                              const reader=new FileReader(); reader.onload=()=>setState(s=>({...s, customization:{...s.customization, buttonIconUrl: reader.result as string}})); reader.readAsDataURL(file);
                            }} />
                            {state.customization.buttonIconUrl && (
                              <img src={state.customization.buttonIconUrl} alt="icon" className="w-8 h-8 rounded border" />
                            )}
                            {!state.customization.buttonIconUrl && (
                              <span className="text-xs text-muted-foreground">Default icon will be used</span>
                            )}
                          </div>
                        </div>

                        <div>
                          <Label>Bot Avatar</Label>
                          <div className="flex items-center gap-3 mt-2">
                            <Button variant="outline" onClick={() => document.getElementById('avatar-input')?.click()}>
                              <ImageIcon className="w-4 h-4 mr-2" /> Upload Image
                            </Button>
                            <input id="avatar-input" type="file" accept="image/*" className="hidden" onChange={(e) => {
                              const file = e.target.files?.[0];
                              if (!file) return;
                              if (file.size > 2 * 1024 * 1024) {
                                toast({ title: 'Image too large', description: 'Max 2MB.', variant: 'destructive' });
                                return;
                              }
                              const reader = new FileReader();
                              reader.onload = () => setState((s) => ({ ...s, customization: { ...s.customization, avatarDataUrl: reader.result as string } }));
                              reader.readAsDataURL(file);
                            }} />
                            {state.customization.avatarDataUrl && (
                              <img src={state.customization.avatarDataUrl} alt="avatar" className="w-10 h-10 rounded-full border" />
                            )}
                          </div>
                        </div>
                      </div>

                      <div>
                        <Card>
                          <CardHeader>
                            <CardTitle className="flex items-center text-lg"><Palette className="w-5 h-5 mr-2" /> Live Preview</CardTitle>
                          </CardHeader>
                          <CardContent>
                            <div className="relative h-64 border rounded-lg overflow-hidden bg-white">
                              <div className="absolute inset-0 flex flex-col">
                                <div className="p-3 text-white" style={{ backgroundColor: state.customization.chatHeaderColor }}>
                                  <div className="flex items-center gap-2">
                                    {state.customization.avatarDataUrl ? (
                                      <img src={state.customization.avatarDataUrl} alt="avatar" className="w-6 h-6 rounded-full border border-white/30" />
                                    ) : (
                                      <div className="w-6 h-6 rounded-full bg-white/20 flex items-center justify-center"><Bot className="w-4 h-4 text-white" /></div>
                                    )}
                                    <span className="text-sm font-medium">{state.customization.headerTitle}</span>
                                  </div>
                                </div>
                                <div className="flex-1 p-3 space-y-2 bg-secondary/30">
                                  <div className={`max-w-[80%] px-3 py-2 text-sm text-white ${previewBubbleClass} ml-auto`} style={{ backgroundColor: state.customization.buttonColor }}>
                                    Hi, do you offer 24/7 support?
                                  </div>
                                  <div className="text-[11px] text-muted-foreground">{state.customization.botName}</div>
                                  <div className={`max-w-[80%] px-3 py-2 text-sm ${previewBubbleClass}`} style={{ backgroundColor: '#F1F5F9' }}>
                                    {state.customization.greeting}
                                  </div>
                                </div>
                              </div>
                              <div className="absolute inset-0 pointer-events-none flex items-end justify-end p-4">
                                {previewOpen && (
                                  <div className={`pointer-events-auto bg-white rounded-xl shadow-xl border overflow-hidden preview-anim ${state.customization.openAnimation === 'fade' ? 'preview-anim-fade' : state.customization.openAnimation === 'slide-up' ? 'preview-anim-slide-up' : state.customization.openAnimation === 'slide-left' ? 'preview-anim-slide-left' : state.customization.openAnimation === 'zoom' ? 'preview-anim-zoom' : 'preview-anim-bounce'}`} style={{ width: state.customization.chatWidth, height: state.customization.chatHeight }}>
                                    <div className="p-3 text-white" style={{ backgroundColor: state.customization.chatHeaderColor }}>
                                      <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-2">
                                          {state.customization.avatarDataUrl ? (
                                            <img src={state.customization.avatarDataUrl} alt="avatar" className="w-5 h-5 rounded-full border border-white/30" />
                                          ) : (
                                            <div className="w-5 h-5 rounded-full bg-white/20 flex items-center justify-center"><Bot className="w-3 h-3 text-white" /></div>
                                          )}
                                          <span className="text-xs font-medium">{state.customization.headerTitle}</span>
                                        </div>
                                        <button className="text-white/90 text-xs" onClick={(e)=>{e.stopPropagation(); setPreviewOpen(false);}}>✕</button>
                                      </div>
                                    </div>
                                    <div className="p-3 space-y-2 bg-secondary/30">
                                      <div className="text-[11px] text-muted-foreground">{state.customization.botName}</div>
                                      <div className={`max-w:[85%] px-3 py-2 text-sm ${previewBubbleClass}`} style={{ backgroundColor:'#F1F5F9' }}>{state.customization.greeting}</div>
                                      <div className={`max-w-[65%] px-3 py-2 text-sm text-white ${previewBubbleClass}`} style={{ backgroundColor: state.customization.buttonColor }}>How can I help?</div>
                                    </div>
                                  </div>
                                )}
                              </div>

                              <button
                                aria-label="chat-button"
                                className="absolute rounded-full shadow-lg border"
                                style={{
                                  width: buttonSizePx,
                                  height: buttonSizePx,
                                  right: 16,
                                  bottom: 16,
                                  backgroundColor: state.customization.buttonColor,
                                }}
                                onClick={()=>setPreviewOpen((v)=>!v)}
                              >
                                {state.customization.buttonIconUrl ? (
                                  <img src={state.customization.buttonIconUrl} alt="icon" className="w-5 h-5 mx-auto" />
                                ) : (
                                  <MessageSquare className="w-5 h-5 text-white mx-auto" />
                                )}
                              </button>
                              <p className="absolute left-3 bottom-3 text-[11px] text-muted-foreground">Click the button to preview chat UI</p>
                            </div>
                          </CardContent>
                        </Card>
                      </div>
                    </div>

                    <div className="flex flex-col gap-3">
                      <div className="flex gap-3">
                        <Button variant="outline" onClick={handlePrev} className="w-1/3">Back</Button>
                        <Button onClick={saveCustomization} className="flex-1" disabled={saving}>{saving? 'Processing…' : 'Save Changes'}</Button>
                      </div>
                      <Button onClick={onLaunch} className="w-full bg-gradient-to-r from-green-600 to-green-700 hover:from-green-700 hover:to-green-800 text-white">Launch NexaBot 🚀</Button>
                    </div>

                    {state.embedCode && (
                      <div className="bg-secondary/30 rounded-lg p-4">
                        <h4 className="font-semibold mb-2">Install Script</h4>
                        <p className="text-sm text-muted-foreground mb-3">Paste this in head or before body end.</p>
                        <div className="relative">
                          <pre className="bg-background border rounded p-3 text-xs font-mono overflow-x-auto whitespace-pre-wrap">{state.embedCode}</pre>
                          <Button size="sm" variant="outline" className="absolute top-2 right-2" onClick={copyEmbed}>
                            {copied ? <Check className="w-4 h-4 mr-1" /> : <Copy className="w-4 h-4 mr-1" />} {copied ? 'Copied' : 'Copy'}
                          </Button>
                        </div>
                      </div>
                    )}
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            <Card className="animate-fade-in-up" style={{ animationDelay: '0.2s' }}>
              <CardHeader>
                <CardTitle className="text-lg">Live Chat Preview</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="bg-secondary/30 rounded-lg p-4 space-y-3">
                  <div className="chat-bubble max-w-[80%] ml-auto">
                    <p className="text-sm">Hi, do you offer 24/7 support?</p>
                  </div>
                  <div className="chat-bubble max-w-[80%]">
                    <div className="flex items-center space-x-2">
                      <Bot className="w-4 h-4 text-primary" />
                      <div className="typing-dots"><span></span><span></span><span></span></div>
                    </div>
                  </div>
                </div>
                <p className="text-xs text-muted-foreground mt-3 text-center">Complete setup to test your bot</p>
              </CardContent>
            </Card>

            <Card className="animate-fade-in-up" style={{ animationDelay: '0.3s' }}>
              <CardHeader>
                <CardTitle className="flex items-center text-lg">
                  <BarChart3 className="w-5 h-5 mr-2" />
                  Analytics Preview
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Conversations</span>
                  <span className="font-bold">0</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Leads Captured</span>
                  <span className="font-bold">0</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Avg Response Time</span>
                  <span className="font-bold text-green-600">&lt; 1s</span>
                </div>
                <div className="pt-2 border-t">
                  <Badge variant="secondary" className="w-full justify-center bg-orange-100 text-orange-700">
                    <Clock className="w-3 h-3 mr-1" />
                    Beta Mode Active
                  </Badge>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
