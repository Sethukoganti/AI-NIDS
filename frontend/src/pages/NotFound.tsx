import { Link } from 'react-router-dom'
import { Compass, Home } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'

export function NotFound() {
  return (
    <div className="grid min-h-[70vh] place-items-center px-4">
      <Card className="max-w-md p-8 text-center">
        <Compass className="mx-auto h-8 w-8 text-primary" />
        <h1 className="mt-3 text-lg font-semibold tracking-tight">Page not found</h1>
        <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
          The page you were looking for does not exist in the AI-NIDS console. It may have been removed, or the
          link may be out of date.
        </p>
        <div className="mt-5 flex justify-center gap-2">
          <Button asChild size="sm">
            <Link to="/dashboard">
              <Home className="h-3.5 w-3.5" />
              Go to dashboard
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm">
            <Link to="/">Overview</Link>
          </Button>
        </div>
      </Card>
    </div>
  )
}
