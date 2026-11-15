import { Compass } from "lucide-react";
import { Link } from "react-router-dom";

import { EmptyState } from "@/components/states";
import { Button } from "@/components/ui/button";

export default function NotFoundPage() {
  return (
    <EmptyState
      icon={Compass}
      title="Page not found"
      description="That page does not exist. Use the sidebar to get back on track."
      action={
        <Button asChild>
          <Link to="/">Go to overview</Link>
        </Button>
      }
    />
  );
}
