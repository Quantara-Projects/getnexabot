import React, { useEffect, useRef, useState } from 'react';

export const useInView = <T extends HTMLElement>(options?: IntersectionObserverInit) => {
  const ref = useRef<T | null>(null);
  const [inView, setInView] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;

    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => setInView(entry.isIntersecting));
    }, { threshold: 0.15, rootMargin: '0px 0px -10% 0px', ...(options || {}) });

    observer.observe(el);
    return () => observer.disconnect();
  }, [options]);

  return { ref, inView } as const;
};

export const Reveal: React.FC<{ className?: string, once?: boolean, children: React.ReactNode }>
  = ({ className, once = true, children }) => {
  const { ref, inView } = useInView<HTMLDivElement>();
  const [hasShown, setHasShown] = useState(false);

  useEffect(() => {
    if (inView) setHasShown(true);
  }, [inView]);

  const shouldAnimate = once ? (inView && !hasShown ? true : inView && !hasShown) : inView;
  const visible = inView || (once && hasShown);

  return (
    <div
      ref={ref}
      className={[
        'transition-all duration-700 ease-out will-change-transform',
        visible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-6',
        shouldAnimate ? 'animate-fade-in-up' : '',
        className || ''
      ].join(' ')}
    >
      {children}
    </div>
  );
};
