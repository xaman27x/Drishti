import { useEffect, useState } from "react";

export function useResource(loader, dependencies = []) {
  const [state, setState] = useState({ data: null, loading: true, error: null });

  useEffect(() => {
    let active = true;
    setState((current) => ({ ...current, loading: true, error: null }));
    loader()
      .then((data) => active && setState({ data, loading: false, error: null }))
      .catch((error) => active && setState({ data: null, loading: false, error }));

    return () => {
      active = false;
    };
  }, dependencies);

  return state;
}