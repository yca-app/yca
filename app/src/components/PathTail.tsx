import { useEffect, useLayoutEffect, useRef, useState } from "react";

import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

// Asked once: the home folder does not move while the app runs.
let home: Promise<string> | undefined;

/** A path with the home folder written as `~`, the way people say it and
 *  short enough to fit in most places. */
export function useShortPath(path: string): string {
  const [homeDir, setHomeDir] = useState<string | null>(null);
  useEffect(() => {
    let wanted = true;
    (home ??= api.homeDir()).then(
      (dir) => wanted && setHomeDir(dir),
      // Without it the path is simply shown in full.
      () => {},
    );
    return () => {
      wanted = false;
    };
  }, []);
  return homeDir && (path === homeDir || path.startsWith(`${homeDir}/`))
    ? `~${path.slice(homeDir.length)}`
    : path;
}

/**
 * The path of a folder on one line, with its end always in view: the end
 * is what tells one folder from another.
 *
 * The home folder is written as `~`, which makes most paths fit. One that
 * still does not is cut at its start and fades out there. The cut is not
 * left to the browser's own ellipsis, which the app's web view draws in
 * the middle of a letter when it has to truncate at the start of a line.
 */
export function PathTail({ path, className }: { path: string; className?: string }) {
  const shown = useShortPath(path);

  const outer = useRef<HTMLParagraphElement>(null);
  const inner = useRef<HTMLSpanElement>(null);
  const [cut, setCut] = useState(false);
  useLayoutEffect(() => {
    const measure = () => {
      if (outer.current && inner.current) {
        setCut(inner.current.offsetWidth > outer.current.clientWidth);
      }
    };
    measure();
    const observer = new ResizeObserver(measure);
    if (outer.current) observer.observe(outer.current);
    return () => observer.disconnect();
  }, [shown]);

  return (
    <p
      ref={outer}
      className={cn(
        "flex overflow-hidden whitespace-nowrap",
        // Pushed to the right, a path that is too long loses its start.
        cut && "justify-end [mask-image:linear-gradient(to_right,transparent,black_1.5rem)]",
        className,
      )}
    >
      <span ref={inner} className="shrink-0">
        {shown}
      </span>
    </p>
  );
}
