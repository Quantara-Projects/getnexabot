import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App.tsx";
import { AuthProvider } from "./hooks/useAuth";
import "./index.css";
import ErrorOverlay from "./components/ErrorOverlay";

createRoot(document.getElementById("root")!).render(
  <BrowserRouter>
    <ErrorOverlay />
    <AuthProvider>
      <App />
    </AuthProvider>
  </BrowserRouter>
);
