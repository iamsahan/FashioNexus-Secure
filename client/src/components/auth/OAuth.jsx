import { GoogleAuthProvider, getAuth, signInWithPopup } from "firebase/auth";
import { app } from "../../firebase";
import { useDispatch } from "react-redux";
import { signInSuccess } from "../../redux/user/userSlice";
import { useNavigate } from "react-router-dom";
import { FaGoogle } from "react-icons/fa";
import { motion, AnimatePresence } from "framer-motion";

export default function OAuth() {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const handleGoogleClick = async () => {
    try {
      const provider = new GoogleAuthProvider();
      // Add custom parameters to avoid COOP issues
      provider.setCustomParameters({
        prompt: 'select_account'
      });
      const auth = getAuth(app);

      // Use signInWithPopup with proper error handling
      const result = await signInWithPopup(auth, provider).catch((popupError) => {
        // If popup is blocked, provide user feedback
        if (popupError.code === 'auth/popup-blocked') {
          alert('Please allow popups for this site to sign in with Google');
        } else if (popupError.code === 'auth/popup-closed-by-user') {
          console.log('Popup closed by user');
        } else if (popupError.code === 'auth/cancelled-popup-request') {
          console.log('Popup request cancelled');
        }
        throw popupError;
      });

      const idToken = await result.user.getIdToken();
      const res = await fetch("/api/auth/google", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ idToken }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || "Google auth failed");
      console.log("OAuth - User data received:", data);
      console.log("OAuth - Dispatching user:", { ...data.user, accessToken: data.accessToken });
      dispatch(signInSuccess({ ...data.user, accessToken: data.accessToken }));
      navigate("/");
    } catch (error) {
      console.log("could not sign in with google", error);
    }
  };
  return (
    <motion.button
      className="w-full mt-4 py-2 px-4 bg-red-600 text-white rounded-md font-semibold shadow-md hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-opacity-50 flex items-center justify-center"
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.98 }}
      onClick={handleGoogleClick}
    >
      <FaGoogle className="mr-2" />
      Sign In with Google
    </motion.button>
  );
}
