import type { Metadata } from "next"
import { GatewayView } from "@/components/gateway/gateway-view"

export const metadata: Metadata = {
  title: "Live Threat Gateway — TraceGuard",
  description: "Real-time interception of inbound messages across email, SMS, and social channels.",
}

export default function MonitoringPage() {
  return <GatewayView />
}
