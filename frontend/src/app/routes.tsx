import { createBrowserRouter } from "react-router";
import Landing from "./pages/Landing";
import Analyzing from "./pages/Analyzing";
import Result from "./pages/Result";
import Auth from "./pages/Auth";
import { ProtectedRoute } from "./components/ProtectedRoute";

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