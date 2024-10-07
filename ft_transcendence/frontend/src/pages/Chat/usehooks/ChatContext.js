import React, {createContext, useState, useEffect} from "react";
import useFetch from "../../../hooks/useFetch.js";
import useAuth from "../../../hooks/useAuth.js";
import { SuccessToast } from "../../../components/ReactToastify/SuccessToast.js";
import { ErrorToast } from "../../../components/ReactToastify/ErrorToast.js";


const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const WS_BACKEND_URL = process.env.REACT_APP_WS_BACKEND_URL;

export const CurrentUserContext = createContext()

export const CurrentUserProvider = ({children}) =>{

const {data:CurrentUser} = useFetch(`${BACKEND_URL}/user/stats/`)
return (
    <CurrentUserContext.Provider value={CurrentUser}>
        {children}
    </CurrentUserContext.Provider>
)
}

export const blockPopUpContext = createContext()

export const BlockPopUpProvider = ({children}) =>{
  const [blockpopUp, setblockpopUp] = useState(false);

  return (
    <blockPopUpContext.Provider value={{blockpopUp: blockpopUp, setblockpopUp: setblockpopUp}}>
        {children}
    </blockPopUpContext.Provider>
)
}

export const clientSocketContext = createContext();

export const SocketClientProvider = ({children}) =>{
    const [socket, setsocket] = useState(null);
    const [botSocket, setbotSocket] = useState(null);
    const { auth } = useAuth();
    const [eventData , seteventReceived ] = useState(null);


  useEffect(() => {
    if (!auth.accessToken)
        return;
    const clientSocket = new WebSocket(`${WS_BACKEND_URL}/ws/chat/?token=${auth.accessToken}`);
    const forBotSocket = new WebSocket(`${WS_BACKEND_URL}/ws/chatbot/?token=${auth.accessToken}`)
    
    clientSocket.onopen = () => {
        setsocket(clientSocket);
        SuccessToast(" Clunca WebSocket instanciated")
    };

    clientSocket.onclose = () => {
      ErrorToast('Clunca WebSocket closed (onclose)');
    };

    clientSocket.onerror = (error)=>{
      ErrorToast('Clunca WebSocket error (onerror)');
    }

    // ****************************************************************************************
    forBotSocket.onopen = () => {
        setbotSocket(forBotSocket);
        SuccessToast(" ChatBot WebSocket instanciated (onopen)")
    };

    forBotSocket.onclose = () => {
      ErrorToast('ChatBot WebSocket closed (onclose)');
    };

    forBotSocket.onerror = (error)=>{
      ErrorToast('ChatBot WebSocket error');
    }
    forBotSocket.onmessage = (event) =>{
      const eventdata = JSON.parse(event.data);
      seteventReceived(eventdata)
    }
    // ****************************************************************************************
    return () => {
      if (socket){
        socket.close();
        if (clientSocket)
          clientSocket.close();
      }
      if (botSocket){
        botSocket.close();
        if (forBotSocket)
          forBotSocket.close();
      }
    
    };
  }, [auth.accessToken]);

    const socketstate ={
        stateValue : socket,
        socketsetter: setsocket,
        botSocket : botSocket,
        eventData: eventData
    }
    
return (
    <clientSocketContext.Provider value={socketstate}>
        {children}
    </clientSocketContext.Provider>
)
}
