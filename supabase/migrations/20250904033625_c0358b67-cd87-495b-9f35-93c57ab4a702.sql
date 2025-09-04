-- Create user profiles table
CREATE TABLE public.profiles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL UNIQUE,
  full_name TEXT,
  business_name TEXT,
  website_url TEXT,
  phone TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Create user settings table for customization
CREATE TABLE public.user_settings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL UNIQUE,
  theme_primary_color TEXT DEFAULT '#0ea5e9',
  theme_secondary_color TEXT DEFAULT '#8b5cf6',
  website_url TEXT,
  setup_completed BOOLEAN DEFAULT false,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Create uploaded files table for bot training
CREATE TABLE public.uploaded_files (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
  filename TEXT NOT NULL,
  file_path TEXT NOT NULL,
  file_type TEXT NOT NULL,
  file_size INTEGER NOT NULL,
  upload_date TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Create chatbot configurations table
CREATE TABLE public.chatbot_configs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL UNIQUE,
  bot_name TEXT DEFAULT 'NexaBot',
  welcome_message TEXT DEFAULT 'Hello! How can I help you today?',
  training_status TEXT DEFAULT 'pending' CHECK (training_status IN ('pending', 'training', 'completed', 'failed')),
  is_active BOOLEAN DEFAULT false,
  whatsapp_connected BOOLEAN DEFAULT false,
  messenger_connected BOOLEAN DEFAULT false,
  website_connected BOOLEAN DEFAULT false,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Create security logs table
CREATE TABLE public.security_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  ip_address INET,
  user_agent TEXT,
  success BOOLEAN NOT NULL,
  details JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Create captcha attempts table
CREATE TABLE public.captcha_attempts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id TEXT NOT NULL,
  ip_address INET NOT NULL,
  attempts INTEGER DEFAULT 1,
  last_attempt TIMESTAMP WITH TIME ZONE DEFAULT now(),
  blocked_until TIMESTAMP WITH TIME ZONE
);

-- Enable RLS on all tables
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.uploaded_files ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chatbot_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.captcha_attempts ENABLE ROW LEVEL SECURITY;

-- RLS policies for profiles
CREATE POLICY "Users can view their own profile" ON public.profiles
  FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can insert their own profile" ON public.profiles
  FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users can update their own profile" ON public.profiles
  FOR UPDATE USING (auth.uid() = user_id);

-- RLS policies for user_settings
CREATE POLICY "Users can view their own settings" ON public.user_settings
  FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can insert their own settings" ON public.user_settings
  FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users can update their own settings" ON public.user_settings
  FOR UPDATE USING (auth.uid() = user_id);

-- RLS policies for uploaded_files
CREATE POLICY "Users can view their own files" ON public.uploaded_files
  FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can insert their own files" ON public.uploaded_files
  FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users can delete their own files" ON public.uploaded_files
  FOR DELETE USING (auth.uid() = user_id);

-- RLS policies for chatbot_configs
CREATE POLICY "Users can view their own chatbot config" ON public.chatbot_configs
  FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can insert their own chatbot config" ON public.chatbot_configs
  FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users can update their own chatbot config" ON public.chatbot_configs
  FOR UPDATE USING (auth.uid() = user_id);

-- RLS policies for security_logs (users can only view their own)
CREATE POLICY "Users can view their own security logs" ON public.security_logs
  FOR SELECT USING (auth.uid() = user_id);

-- RLS policies for captcha_attempts (public read for validation)
CREATE POLICY "Anyone can view captcha attempts for validation" ON public.captcha_attempts
  FOR SELECT TO public USING (true);
CREATE POLICY "Anyone can insert captcha attempts" ON public.captcha_attempts
  FOR INSERT TO public WITH CHECK (true);
CREATE POLICY "Anyone can update captcha attempts" ON public.captcha_attempts
  FOR UPDATE TO public USING (true);

-- Create file storage bucket for user uploads
INSERT INTO storage.buckets (id, name, public) VALUES ('user-files', 'user-files', false);

-- Storage policies for user files
CREATE POLICY "Users can upload their own files" ON storage.objects
  FOR INSERT WITH CHECK (bucket_id = 'user-files' AND auth.uid()::text = (storage.foldername(name))[1]);

CREATE POLICY "Users can view their own files" ON storage.objects
  FOR SELECT USING (bucket_id = 'user-files' AND auth.uid()::text = (storage.foldername(name))[1]);

CREATE POLICY "Users can delete their own files" ON storage.objects
  FOR DELETE USING (bucket_id = 'user-files' AND auth.uid()::text = (storage.foldername(name))[1]);

-- Create function to update timestamps
CREATE OR REPLACE FUNCTION public.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create triggers for automatic timestamp updates
CREATE TRIGGER update_profiles_updated_at
  BEFORE UPDATE ON public.profiles
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER update_user_settings_updated_at
  BEFORE UPDATE ON public.user_settings
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER update_chatbot_configs_updated_at
  BEFORE UPDATE ON public.chatbot_configs
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

-- Function to log security events
CREATE OR REPLACE FUNCTION public.log_security_event(
  p_user_id UUID,
  p_action TEXT,
  p_ip_address INET,
  p_user_agent TEXT,
  p_success BOOLEAN,
  p_details JSONB DEFAULT NULL
) RETURNS void AS $$
BEGIN
  INSERT INTO public.security_logs (user_id, action, ip_address, user_agent, success, details)
  VALUES (p_user_id, p_action, p_ip_address, p_user_agent, p_success, p_details);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;