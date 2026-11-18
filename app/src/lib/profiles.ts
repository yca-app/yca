// What a certificate can be for, in the order the choices are offered,
// and the picture that stands for each.

import { Laptop, Monitor, Router, Server, type LucideIcon } from "lucide-react";

import type { Profile } from "@/lib/api";

export const profiles: Profile[] = ["tls-server", "ipsec-gateway", "ipsec-client", "tls-client"];

export const profileIcon: Record<Profile, LucideIcon> = {
  "tls-server": Server,
  "tls-client": Monitor,
  "ipsec-gateway": Router,
  "ipsec-client": Laptop,
};
