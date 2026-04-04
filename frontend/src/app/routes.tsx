import { createBrowserRouter, Navigate } from "react-router";
import { useAuth } from "./contexts/AuthContext";
import Landing from "./pages/Landing";
import Analyzing from "./pages/Analyzing";
import Result from "./pages/Result";
import Auth from "./pages/Auth";

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { currentUser, loading } = useAuth();
  
  if (loading) return null; // or a loading spinner
  
  if (!currentUser) {
    return <Navigate to="/auth" replace />;
  }

  return <>{children}</>;
}

export const router = createBrowserRouter([
  {
    path: "/",
    element: <Landing />,
  },
  {
    path: "/analyzing",
    element: (
      <ProtectedRoute>
        <Analyzing />
      </ProtectedRoute>
    ),
  },
  {
    path: "/result",
    element: (
      <ProtectedRoute>
        <Result />
      </ProtectedRoute>
    ),
  },
  {
    path: "/auth",
    element: <Auth />,
  },
]);