import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";
import { getFirestore } from "firebase/firestore";

const firebaseConfig = {
  apiKey: "AIzaSyCd-YDoFY8nrXuBU35zx_m63Uq7iHpj4gY",
  authDomain: "hackup-5a6c1.firebaseapp.com",
  projectId: "hackup-5a6c1",
  storageBucket: "hackup-5a6c1.firebasestorage.app",
  messagingSenderId: "276992566774",
  appId: "1:276992566774:web:0167be6620d8a5f1fbd3d7",
  measurementId: "G-N4XPJEV6WW"
};

const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);
