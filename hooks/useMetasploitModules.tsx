import { useEffect, useState } from "react";

export function useMetasploitModules(page = 1, pageSize = 100) {
  const [modules, setModules] = useState<string[]>([]);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch(`http://localhost:8000/api/metasploit/modules/?page=${page}&page_size=${pageSize}`)
      .then((res) => res.json())
      .then((data) => {
        if (data.modules) {
          setModules(data.modules);
          setTotal(data.total);
          setTotalPages(data.total_pages);
        } else {
          setError(data.error || "Unknown error");
        }
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message);
        setLoading(false);
      });
  }, [page, pageSize]);

  return { modules, total, totalPages, loading, error };
} 