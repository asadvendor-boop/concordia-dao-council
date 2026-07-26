import { PUBLIC_LINKS } from "./presentation-config.mjs";

export function PublicLinkList({ className = "", ids = null }) {
  const allowed = ids ? new Set(ids) : null;
  const links = allowed ? PUBLIC_LINKS.filter((link) => allowed.has(link.id)) : PUBLIC_LINKS;
  return <div className={className}>
    {links.map((link) => <a
      key={link.id}
      href={link.href}
      target="_blank"
      rel="noopener noreferrer"
    >
      {link.label}
    </a>)}
  </div>;
}
