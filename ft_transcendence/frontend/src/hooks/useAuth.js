import { useContext } from "react";
import AuthContext from "../context/Auth/AuthProvider";


const useAuth = () => {
  return useContext(AuthContext);
}

export default useAuth