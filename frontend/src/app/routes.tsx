import { createBrowserRouter } from "react-router";
import Landing from "./pages/Landing";
import Analyzing from "./pages/Analyzing";
import Result from "./pages/Result";
import Auth from "./pages/Auth";

export const router = createBrowserRouter([
  {
    path: "/",
    element: <Landing />,
  },
  {
    path: "/analyzing",
    element: <Analyzing />,
  },
  {
    path: "/result",
    element: <Result />,
  },
  {
    path: "/auth",
    element: <Auth />,
  },
]);