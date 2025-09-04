// src/components/ErrorOverlay.tsx
import { useEffect, useState } from "react";

export default function ErrorOverlay() {
  const [hasError, setHasError] = useState(false);

  useEffect(() => {
    // Catch global JS errors
    const handleError = () => {
      setHasError(true);
    };

    window.addEventListener("error", handleError);
    window.addEventListener("unhandledrejection", handleError);

    return () => {
      window.removeEventListener("error", handleError);
      window.removeEventListener("unhandledrejection", handleError);
    };
  }, []);

  if (!hasError) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 text-center px-4">
      <div className="bg-white rounded-2xl shadow-lg p-6 max-w-md w-full animate-bounce">
        <h1 className="text-xl sm:text-2xl font-bold text-red-600 mb-2">
          UH-OH AN ERROR OCCURED
        </h1>
        <p className="text-gray-700 text-lg">
          NEXABOT IS ON ITS WAY TO FIX IT 🦾
        </p>
      </div>
    </div>
  );
}
