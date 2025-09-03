import { ArrowLeft, Bot, Calendar, Clock, ArrowRight } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { useNavigate } from 'react-router-dom';

const Blog = () => {
  const navigate = useNavigate();

  const blogPosts = [
    {
      id: 1,
      title: "How AI Chatbots Are Revolutionizing Customer Support in 2025",
      excerpt: "Discover the latest trends in AI customer support and how businesses are achieving 90% query resolution rates with intelligent chatbots.",
      category: "AI Technology",
      readTime: "5 min read",
      date: "March 15, 2025",
      image: "🤖",
      featured: true
    },
    {
      id: 2,
      title: "The Complete Guide to Setting Up Your First Business Chatbot",
      excerpt: "Step-by-step tutorial on creating, training, and deploying your first AI chatbot without any coding experience.",
      category: "Tutorial",
      readTime: "8 min read",
      date: "March 12, 2025",
      image: "📚"
    },
    {
      id: 3,
      title: "WhatsApp Business API: Automate Customer Support on the World's Most Popular Messaging App",
      excerpt: "Learn how to integrate your chatbot with WhatsApp Business API to reach 2 billion users worldwide.",
      category: "Integration",
      readTime: "6 min read",
      date: "March 10, 2025",
      image: "💬"
    },
    {
      id: 4,
      title: "Case Study: How TechStart Increased Lead Conversion by 340% with NexaBot",
      excerpt: "Real results from a SaaS startup that transformed their customer acquisition with AI-powered chat support.",
      category: "Case Study",
      readTime: "7 min read",
      date: "March 8, 2025",
      image: "📈"
    },
    {
      id: 5,
      title: "The Psychology of Instant Response: Why Speed Matters in Customer Support",
      excerpt: "Research-backed insights on customer expectations and how response time directly impacts sales and satisfaction.",
      category: "Psychology",
      readTime: "4 min read",
      date: "March 5, 2025",
      image: "🧠"
    },
    {
      id: 6,
      title: "Building Multi-Language Chatbots: Expanding Your Global Reach",
      excerpt: "How to create chatbots that communicate fluently in multiple languages to serve international customers.",
      category: "Global Strategy",
      readTime: "6 min read",
      date: "March 3, 2025",
      image: "🌍"
    }
  ];

  const categories = ["All", "AI Technology", "Tutorial", "Integration", "Case Study", "Psychology", "Global Strategy"];

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-secondary/10 to-background">
      {/* Header */}
      <header className="border-b bg-white/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 sm:px-6 py-4">
          <div className="flex items-center space-x-4">
            <Button 
              variant="ghost" 
              onClick={() => navigate('/')}
              className="text-muted-foreground hover:text-foreground"
            >
              <ArrowLeft className="w-4 h-4 mr-2" />
              Back to Home
            </Button>
            <div className="flex items-center space-x-3">
              <div className="bg-gradient-to-r from-primary to-violet-600 p-2 rounded-lg">
                <Bot className="w-5 h-5 text-white" />
              </div>
              <h1 className="text-lg sm:text-xl font-bold">NexaBot Blog</h1>
            </div>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-4 sm:px-6 py-8 sm:py-12">
        {/* Hero Section */}
        <div className="text-center mb-12 sm:mb-16">
          <h1 className="text-3xl sm:text-4xl lg:text-5xl font-bold mb-6">
            The <span className="bg-gradient-to-r from-primary to-violet-600 bg-clip-text text-transparent">Future</span> of Customer Support
          </h1>
          <p className="text-lg sm:text-xl text-muted-foreground max-w-3xl mx-auto leading-relaxed">
            Insights, tutorials, and case studies on AI chatbots, customer support automation, and business growth strategies.
          </p>
        </div>

        {/* Categories */}
        <div className="flex flex-wrap gap-2 sm:gap-3 justify-center mb-8 sm:mb-12">
          {categories.map((category) => (
            <Badge 
              key={category}
              variant={category === "All" ? "default" : "outline"}
              className="cursor-pointer hover:bg-primary hover:text-white transition-smooth px-3 py-1 text-xs sm:text-sm"
            >
              {category}
            </Badge>
          ))}
        </div>

        {/* Featured Post */}
        {blogPosts.filter(post => post.featured).map((post) => (
          <Card key={post.id} className="mb-8 sm:mb-12 animate-fade-in-up overflow-hidden">
            <div className="grid lg:grid-cols-2 gap-0">
              <div className="bg-gradient-to-br from-primary/10 to-violet-600/10 p-8 sm:p-12 flex items-center justify-center">
                <div className="text-center">
                  <div className="text-6xl sm:text-8xl mb-4">{post.image}</div>
                  <Badge className="bg-gradient-to-r from-primary to-violet-600 text-white">
                    Featured Post
                  </Badge>
                </div>
              </div>
              <CardContent className="p-6 sm:p-8 lg:p-12 flex flex-col justify-center">
                <Badge variant="outline" className="w-fit mb-4">{post.category}</Badge>
                <CardTitle className="text-xl sm:text-2xl lg:text-3xl mb-4 leading-tight">
                  {post.title}
                </CardTitle>
                <p className="text-muted-foreground mb-6 text-sm sm:text-base leading-relaxed">
                  {post.excerpt}
                </p>
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4 text-xs sm:text-sm text-muted-foreground">
                    <div className="flex items-center space-x-1">
                      <Calendar className="w-3 h-3 sm:w-4 sm:h-4" />
                      <span>{post.date}</span>
                    </div>
                    <div className="flex items-center space-x-1">
                      <Clock className="w-3 h-3 sm:w-4 sm:h-4" />
                      <span>{post.readTime}</span>
                    </div>
                  </div>
                  <Button variant="outline" className="hover:bg-primary hover:text-white transition-smooth">
                    Read More
                    <ArrowRight className="w-4 h-4 ml-2" />
                  </Button>
                </div>
              </CardContent>
            </div>
          </Card>
        ))}

        {/* Blog Grid */}
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6 sm:gap-8">
          {blogPosts.filter(post => !post.featured).map((post, index) => (
            <Card key={post.id} className="animate-fade-in-up hover:shadow-lg transition-smooth cursor-pointer group" style={{ animationDelay: `${index * 0.1}s` }}>
              <CardHeader className="pb-3">
                <div className="text-3xl sm:text-4xl mb-3 text-center">{post.image}</div>
                <Badge variant="outline" className="w-fit mb-2 text-xs">{post.category}</Badge>
                <CardTitle className="text-lg sm:text-xl leading-tight group-hover:text-primary transition-colors">
                  {post.title}
                </CardTitle>
              </CardHeader>
              <CardContent className="pt-0">
                <p className="text-muted-foreground mb-4 text-sm leading-relaxed">
                  {post.excerpt}
                </p>
                <div className="flex items-center justify-between text-xs text-muted-foreground">
                  <div className="flex items-center space-x-1">
                    <Calendar className="w-3 h-3" />
                    <span>{post.date}</span>
                  </div>
                  <div className="flex items-center space-x-1">
                    <Clock className="w-3 h-3" />
                    <span>{post.readTime}</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Newsletter Signup */}
        <Card className="mt-12 sm:mt-16 bg-gradient-to-r from-primary/10 to-violet-600/10 border-primary/20 animate-fade-in-up">
          <CardContent className="p-6 sm:p-8 lg:p-12 text-center">
            <h2 className="text-2xl sm:text-3xl font-bold mb-4">Stay Updated</h2>
            <p className="text-muted-foreground mb-6 max-w-2xl mx-auto text-sm sm:text-base">
              Get the latest insights on AI chatbots, customer support automation, and business growth delivered to your inbox weekly.
            </p>
            <div className="flex flex-col sm:flex-row gap-3 max-w-md mx-auto">
              <input 
                type="email" 
                placeholder="Enter your email"
                className="flex-1 px-4 py-2 rounded-lg border border-border bg-background focus:outline-none focus:ring-2 focus:ring-primary text-sm"
              />
              <Button className="bg-gradient-to-r from-primary to-violet-600 hover:from-primary/90 hover:to-violet-600/90 text-white px-6">
                Subscribe
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* CTA Section */}
        <div className="text-center mt-12 sm:mt-16 animate-fade-in-up">
          <h2 className="text-2xl sm:text-3xl font-bold mb-6">Ready to Build Your Own AI Chatbot?</h2>
          <p className="text-muted-foreground text-base sm:text-lg mb-8 max-w-2xl mx-auto">
            Stop reading about chatbots and start building one for your business today.
          </p>
          <Button 
            onClick={() => navigate('/signup')}
            className="h-12 px-8 bg-gradient-to-r from-primary to-violet-600 hover:from-primary/90 hover:to-violet-600/90 text-white font-semibold shadow-glow transition-smooth text-base sm:text-lg"
          >
            Start Your Free Beta Trial
          </Button>
        </div>
      </div>
    </div>
  );
};

export default Blog;