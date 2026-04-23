/**
 * P3.1-full — useApi: thin React wrapper around the bearer-token
 * ``apiFetch`` client with optional polling.
 *
 * Replaces the inline ``useApi`` hook that lived at the top of
 * App.jsx; swaps raw ``fetch()`` for ``apiFetch()`` so every request
 * carries the Authorization header (when set).
 *
 * When an ``interval`` is supplied the hook re-fetches every
 * ``interval`` milliseconds; passing ``null`` means "fetch once".
 * For true push-based updates use ``useIncidentStream`` directly.
 */

import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "../api/client";

export function useApi(path, interval = null) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const payload = await apiFetch(path);
      setData(payload);
      setError(null);
    } catch (e) {
      setError(e.message || String(e));
    } finally {
      setLoading(false);
    }
  }, [path]);

  useEffect(() => {
    fetchData();
    if (interval) {
      const id = setInterval(fetchData, interval);
      return () => clearInterval(id);
    }
  }, [fetchData, interval]);

  return { data, error, loading, refresh: fetchData };
}
