import PageShell from "@/components/PageShell";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

const posts = [
  {
    title: "How to prepare your website for an AI support bot",
    category: "Setup",
    summary: "A practical checklist for FAQs, policies, product details, and tone before launching NexaBot.",
  },
  {
    title: "What your chatbot should refuse to answer",
    category: "Safety",
    summary: "Clear boundaries help customers get useful answers while protecting private business rules and credentials.",
  },
  {
    title: "Using AI support without losing the human handoff",
    category: "Support",
    summary: "How to collect leads and route unanswered questions back to the team without making customers wait.",
  },
];

const Blog = () => (
  <PageShell
    eyebrow="Blog"
    title="NexaBot Notes"
    description="Product updates and practical guidance for building reliable AI customer support."
  >
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {posts.map((post) => (
        <Card key={post.title} className="border-border/40">
          <CardContent className="p-6">
            <Badge className="bg-primary/10 text-primary border-primary/20 mb-4">
              {post.category}
            </Badge>
            <h2 className="font-semibold text-lg mb-2">{post.title}</h2>
            <p className="text-sm text-neutral-500 leading-relaxed">{post.summary}</p>
          </CardContent>
        </Card>
      ))}
    </div>
  </PageShell>
);

export default Blog;
