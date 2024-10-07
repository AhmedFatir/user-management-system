import React, { useState, useEffect, createContext, useContext } from "react";
import style from "./Chat.module.css";
import ContactSection from "./Components/ContactSection/ContactSection.jsx";
import MessageSection from "./Components/MessageSection/MessageSection.jsx";
import UserParams from "./Components/UserParams/UserParams";
import useAuth from "../../hooks/useAuth";
import { CurrentUserContext } from "./usehooks/ChatContext.js";
import { clientSocketContext } from "./usehooks/ChatContext.js";
import { blockPopUpContext } from "./usehooks/ChatContext.js";
import receivedmsgsound from "./ChatAssets/receivemsgnotif.mp3"
import { ErrorToast } from "../../components/ReactToastify/ErrorToast.js";


export const conversationMsgContext = createContext();
export const ChatListContext = createContext();
export const PickedConvContext = createContext();
export const conversationSetterContext = createContext();
export const chatPartnerContext = createContext();
// status : false | true ,sender_id : null | value
export const TypingContext = createContext();

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

function reformeDate(datestr) {
  const datetimeObj = new Date(datestr);
  const hours = datetimeObj.getHours();
  const minutes = String(datetimeObj.getMinutes()).padStart(2, "0"); // Convert to string first
  return `${hours}:${minutes}`;
}

const Chat = () => {
  const [ChatList, setChatList] = useState(null);
  const [conversationMsgs, setconversationMsgs] = useState(null);
  const [PickedUsername, setPickerUsername] = useState("");
  const { auth } = useAuth();
  const { stateValue: clientSocket } = useContext(clientSocketContext);
  const CurrentUser = useContext(CurrentUserContext);
  const [ChatPartner, setChatPartner] = useState(null);
  const [requestRefetch, setrequestRefetch] = useState(false);
  const{blockpopUp, setblockpopUp} = useContext(blockPopUpContext)
  const [typingData, setTypingData] = useState({status: false, sender_id: null})

  const  updateUnreadMsgs = (message) =>{
    if (message.receiver_id === CurrentUser?.user_id && message.receiver_id !== message.sender_id){
      setChatList(prevChatList => {
        return prevChatList.map((contact) => {
          if (contact.id === message.sender_id) {
            return {        
                ...contact,
                unreadMessages: contact.unreadMessages + 1
            };
          } else {
            return contact;
          }
        });
      });
    }
}

const alreadyHaveConversation = (id) =>{
    if (ChatList === null)
      return false;
    return ChatList.some((contact) => contact?.id === id)
}

const sortConversations = () =>{
  if (ChatList.length > 1){
    setChatList(prevChatList => {
      const sortedChatList = [...prevChatList].sort((a, b) => {
        return b.created_at.localeCompare(a.created_at);
      });
      return sortedChatList;
    });
  }
}

const update_status = (userdata) =>{
  if (ChatList && ChatList.length){
    setChatList(prev => {
      return prev.map(contact =>{
        if (contact.id === userdata?.status_owner){
          return {...contact, status : userdata?.status}
        }else
          return contact
      })
    })
  }
}

const getContentOrPhoto = (message) =>{
  return message.msgType === 'text' ? message.content : 'shared Photo'
}
const updateLastMessage = (data, result) =>{

  setChatList(prevChatList => {
    return prevChatList.map((contact) => {
      if (contact.id === result[0]?.id) {
        return {        
            ...contact,
            lastTime : reformeDate(data.message.created_at),
            lastMessage : CurrentUser?.user_id === data.message.sender_id ? `You: ${getContentOrPhoto(data.message)}` : `${ChatList?.filter(user => user.id === data.message.sender_id)[0].username.substring(0, 5)}: ${getContentOrPhoto(data.message)}`
        };
      } else {
        return contact;
      }
    });
  });
}
  if (clientSocket) {
    clientSocket.onmessage = (event) => {
    const data = JSON.parse(event.data);
    const notif = new Audio(receivedmsgsound);
    
    if (data.type === 'receive_typing'){
      if (ChatPartner && ChatPartner.id === data.message.sender_id){
      setTypingData({status: true,
        sender_id : data.message.sender_id
      })
    }
    }

    if (data.type === 'deactivate_typing_event'){
      setTypingData({status: false,
        sender_id : data.message.sender_id
      })
    }

    if (data.type === 'status_update'){
      update_status(data.message);
    }

    if (data.type === 'newchat.message'){
      
      // You are receiver you got notif sound! not your self too talk with your self .
      if (data.message.receiver_id === CurrentUser?.user_id && data.message.sender_id !== CurrentUser?.user_id){ 
          notif.play().then(() => {}).catch((error) => {
            // Ignore the error 
          });
            if (alreadyHaveConversation(data.message.sender_id) === false){
              setrequestRefetch(true)
            }
        }
      if (ChatPartner){
        if ((data.message.sender_id === CurrentUser?.user_id && data.message.receiver_id === ChatPartner?.id) ||
          (data.message.sender_id === ChatPartner?.id && data.message.receiver_id === CurrentUser?.user_id)){
            if (data.message.receiver_id === CurrentUser.user_id){
                data.message.seen = true;
                // clientSocket.send Stored on Db as unread but being on a conv is should be setted as read !
                clientSocket.send(JSON.stringify({type : 'Update_msgStatus', messageData : {
                  content : data.message.content,
                  created_at : data.message.created_at,
                  id : data.message.id
                }}))
              }
          setconversationMsgs(prevConversationMsgs => [...prevConversationMsgs, data.message]);
        }
        else{
          // console.log('There is ChatPartner but not required one !') // update unread ! there is a Chatpartner but not required one !
          updateUnreadMsgs(data.message)
        }
        }
        else {
          // console.log('Will Go and Update the unread messages with :=> ' + data.message.sender_id) // no Partner no conversation Selected
          updateUnreadMsgs(data.message)
      }
      sortConversations();
    }
      
    if (data.type === "last.message"){
      let result = ChatList.filter((contact) =>{
        return (contact.id === data.message.sender_id) || (contact.id === data.message.receiver_id)
      })
    if (result.length > 1){
        result= result.filter((Conversation) => Conversation.id !== CurrentUser.user_id)
    }
    updateLastMessage(data, result)
    }

    if (data.type === "msgs.areReaded"){
        setChatList(prevChatList => {
          return prevChatList.map((contact) => {
            if (contact.username === data.message.all_readed_From) {
              return {        
                  ...contact,
                  unreadMessages : 0
              };
            } else {
              return contact;
            }
          });
        });
    }

    if (data.type === "Pick_existed_conv"){
          setPickerUsername(data.message.username)
    }
    
    if (data.type === 'Blocke_Warning'){
      setblockpopUp(true)
      setTimeout(()=>{
        setblockpopUp(false)
      }, 2000)
    }

    if (data.type === 'start_Firstconv'){
      setChatList(prevChatList => {
        if (prevChatList === null) {
          return [data.message];
        } else {
          return [data.message, ...prevChatList];
        }
      });
      setPickerUsername(data.message.username)
    }
  };
}

  useEffect(() => {
    const abortController = new AbortController();
    const FetchContactSection = async () => {
      try {
        const url = `${BACKEND_URL}/chat/GetContactSection/`;
        const response = await fetch(url, {
          method: "GET",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${auth.accessToken}`,
          },
        });
        if (!response.ok) {
          throw new Error(`Response status: ${response.status}`);
        }
        const data = await response.json();
        setChatList(data);
      } catch (error) {
        console.error(error.message);
      }
    };

    FetchContactSection();
    return () => {
      abortController.abort(); 
    };
  }, [requestRefetch, auth.accessToken]);

  const handleConversationSelect = (conversationId) => {
    setPickerUsername(conversationId);
  };

  useEffect(() => {
    const abortController = new AbortController();
    const FetchMessagesSection = async () => {
      try {
        const url = `${BACKEND_URL}/chat/GetMessageswith/${PickedUsername}/`;
        const response = await fetch(url, {
          method: "GET",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${auth.accessToken}`,
          },
        });

        if (!response.ok) {
          throw new Error(`Response status: ${response.status}`);
        }
        const data = await response.json();
        setconversationMsgs(data);
      } catch (error) {
        console.error(error.message);
      }
    };
    if (PickedUsername.length) {
      FetchMessagesSection();
      const PickedConversation = ChatList?.filter(contact => contact.username === PickedUsername)
      // if I protect for PickedConversation this will make error's msgs will not mark_as_Read !
      if (PickedConversation[0]?.unreadMessages){
          clientSocket.send(JSON.stringify({ type: "_mark_msgs_asRead_",
                                               messageData: {With: PickedUsername }}));
        } 
    }
    
    return () => {
      abortController.abort(); // Cancel pending fetch request on component unmount
    };
  }, [PickedUsername, auth.accessToken]);

  return (
    <>
      <h1>Clunca</h1>
      <div className={style.ChatView}>
        <conversationSetterContext.Provider value={setconversationMsgs}>
          <conversationMsgContext.Provider value={conversationMsgs}>
            <ChatListContext.Provider value={{ ChatList, setChatList }}>
              <PickedConvContext.Provider value={PickedUsername}>
              <chatPartnerContext.Provider value={{ChatPartner, setChatPartner}}>
                <TypingContext.Provider value={{status : typingData.status, setTypingData}}>
                  <ContactSection handleConversationSelect={handleConversationSelect} />
                    <MessageSection />
                    {PickedUsername ? <UserParams /> : null}
                    </TypingContext.Provider>
                </chatPartnerContext.Provider>
              </PickedConvContext.Provider>
            </ChatListContext.Provider>
          </conversationMsgContext.Provider>
        </conversationSetterContext.Provider>
      </div>
    </>
  );
};


// function Chat() {
//   const [recording, setRecording] = useState(false);
//   const [mediaRecorder, setMediaRecorder] = useState(null);
//   const [AudioUrl, setAudioUrl] = useState(null);
//   const [error , seterror] = useState("");

//   const startRecording = async () => {
//     try {
//       setRecording(true);
//       setMediaRecorder(null);
//       setAudioUrl(null);
//       seterror("")
  
//       const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
//       const options = { mimeType: 'audio/ogg;codecs=opus' };
//       const newMediaRecorder = new MediaRecorder(stream, options);
//       setMediaRecorder(newMediaRecorder);
  
//       newMediaRecorder.start();
  
//       const audioChunks = [];
//       newMediaRecorder.ondataavailable = event => {
//         audioChunks.push(event.data);
//       };
  
//       newMediaRecorder.onstop = () => {
//         const audioBlob = new Blob(audioChunks);
//         const reader = new FileReader();
//         reader.onloadend = () => {
//           if (reader.result) 
//             setAudioUrl(reader.result);
//     };
//         reader.readAsDataURL(audioBlob);
//     };
    
//     } catch (catchederror) {
//       ErrorToast(catchederror.message);
//       setRecording(false);
//     }
//   };

//   const stopRecording = () => {
//     if (mediaRecorder) {
//       mediaRecorder.stop();
//       setRecording(false);
//     }
//   };

//   return (
//     <div style={{display : 'grid', gridTemplateColumns: '1fr', gridTemplateRows : '1fr 1fr 1fr 1fr'}}>
//       <button onClick={startRecording} disabled={recording}>
//         Start Recording
//       </button>
//       <button onClick={stopRecording} disabled={!recording}>
//         Stop Recording
//       </button>
//       {AudioUrl && <audio controls src={AudioUrl}>Your browser does not support the audio element.</audio>}
//     </div>
//   );
// }

export default Chat;