import { Card, CardContent } from '@/components/ui/card';
import { Clock, MessageCircleX, UserX } from 'lucide-react';

const ProblemSection = () => {
  const problems = [
    {
      icon: Clock,
      title: 'Slow Replies = Lost Sales',
      description: 'Customers expect instant responses. Every delayed reply is a potential lost sale.',
      color: 'text-red-600',
      bgColor: 'bg-red-50'
    },
    {
      icon: MessageCircleX,
      title: 'Repetitive Questions Drain Staff',
      description: 'Your team wastes time answering the same questions over and over again.',
      color: 'text-orange-600',
      bgColor: 'bg-orange-50'
    },
    {
      icon: UserX,
      title: 'No After-Hours Support',
      description: 'Customers need help 24/7, but your business can\'t be awake around the clock.',
      color: 'text-yellow-600',
      bgColor: 'bg-yellow-50'
    }
  ];

  return (
    <section id="problems" className="py-20 bg-secondary/30">
      <div className="container mx-auto px-6">
        <div className="text-center mb-16 animate-fade-in-up">
          <h2 className="text-4xl lg:text-5xl font-bold mb-6">
            Why Businesses Lose Customers
          </h2>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            Every day, businesses lose potential customers due to slow response times and unavailable support. Here's what's costing you money:
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-6xl mx-auto">
          {problems.map((problem, index) => (
            <Card 
              key={index} 
              className="relative overflow-hidden group hover:shadow-xl transition-smooth animate-fade-in-up"
              style={{ animationDelay: `${index * 0.2}s` }}
            >
              <CardContent className="p-8 text-center">
                <div className={`w-16 h-16 ${problem.bgColor} rounded-2xl flex items-center justify-center mx-auto mb-6 group-hover:scale-110 transition-smooth`}>
                  <problem.icon className={`w-8 h-8 ${problem.color}`} />
                </div>
                
                <h3 className="text-xl font-bold mb-4">{problem.title}</h3>
                <p className="text-muted-foreground leading-relaxed">{problem.description}</p>
                
                {/* Decorative element */}
                <div className="absolute -bottom-2 -right-2 w-20 h-20 bg-gradient-to-br from-primary/10 to-violet-500/10 rounded-full blur-xl opacity-0 group-hover:opacity-100 transition-smooth"></div>
              </CardContent>
            </Card>
          ))}
        </div>

        <div className="text-center mt-16">
          <div className="inline-flex items-center px-6 py-3 bg-destructive/10 text-destructive rounded-full font-medium animate-fade-in-up" style={{ animationDelay: '0.8s' }}>
            <UserX className="w-5 h-5 mr-2" />
            Studies show 67% of customers abandon purchases due to poor support
          </div>
        </div>
      </div>
    </section>
  );
};

export default ProblemSection;