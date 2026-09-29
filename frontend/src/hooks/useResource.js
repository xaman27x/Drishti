import { useEffect, useRef, useState } from "react";

export function useResource(loader, dependencies = []) {
  const [state, setState] = useState({ data: null, loading: true, error: null });
  const loaderRef = useRef(loader);
  loaderRef.current = loader;
  useEffect(() => {
    let active = true;
    let timer;
    async function refresh() {
      try {
        const data = await loaderRef.current();
        if (active) setState({ data, loading: false, error: null });
      } catch (error) {
        if (active) setState({ data: null, loading: false, error });
      } finally {
        if (active) timer = window.setTimeout(refresh, 3000);
      }
    }
    setState({ data: null, loading: true, error: null });
    refresh();
    return () => { active = false; window.clearTimeout(timer); };
  }, dependencies);
  return state;
}
