import React, { useState,useRef,useContext, useEffect } from 'react'
import botStyle from './BotIcon.module.css'
import Lottie from 'lottie-react'
import botBody from '../../pages/Chat/ChatAssets/MyChatbot.json'
import online from '../../pages/Chat/ChatAssets/online.json'
import { CurrentUserContext } from '../../pages/Chat/usehooks/ChatContext'
import AuthContext from '../../context/Auth/AuthProvider'
import { UserContext } from '../../context/UserContext'
import { clientSocketContext } from '../../pages/Chat/usehooks/ChatContext'
import { Rnd } from 'react-rnd';
import { useTranslation } from 'react-i18next'



const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;


const BotHeader = () =>{
  const { t } = useTranslation();

  return (
    <div className={botStyle.ChatHeaderHolder}>
        <>
          <div className={botStyle.BotInfo}>
            <Lottie  className={botStyle.BotPhoto} animationData={botBody}/>
            <div className={botStyle.BotnameAndStatus}>
              <div className={botStyle.BotName}> Clunca </div>

              <div className={botStyle.StatusHolder}>
                <div className={botStyle.StatusIcon}>
                  {" "}
                  <Lottie animationData={online} />
                </div>
                <div className={botStyle.Status}>
                  {t("Online")}
                </div>
              </div>
            
            </div>
          </div>
        </>
    </div>
  );
}

function reformeDate(datestr) {
  const datetimeObj = new Date(datestr);
  const hours = datetimeObj.getHours();
  const minutes = String(datetimeObj.getMinutes()).padStart(2, "0"); // Convert to string first
  return `${hours}:${minutes}`;
}

const MessageDisplayer = ({ message, IsIncoming }) => {
  const { userData } = useContext(UserContext);

  return (
    <div style={{color : `${message.color}`}}  className={IsIncoming ? botStyle.MsgIncom : botStyle.MsgOut}>
      <div style={{display : IsIncoming ? 'flex' : 'none'}} className={IsIncoming ? botStyle.receiverAvatar : botStyle.MyAvatar}>
      {IsIncoming === false ?
        <img
          className={botStyle.avatar}
          src={`${BACKEND_URL}` + userData.avatar }
          alt="user-avatar"
        /> : <Lottie  animationData={botBody} style={{ width: '4rem'}}/>}
      </div>

      <div className={botStyle.msgContent}>
        <div className={IsIncoming ? botStyle.incoming : botStyle.outgoing}>
          {" "}
          {message.content}{" "}
        </div>
        <h1 className={IsIncoming ? botStyle.SendingTime : botStyle.SendingTimeout}>
          {reformeDate(message.created_at)}
        </h1>
      </div>
    </div>
  );
};


const MainChat = () =>{
  const { userData } = useContext(UserContext);
  const {eventData} = useContext(clientSocketContext)
  const [conversations, setconversations] = useState([]);
  const messagesEndRef = useRef(null);
  
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  });

  useEffect(()=>{
    if (eventData?.type === 'bot_msg'){
      setconversations(prev => { 
        return  !prev.length ?  [eventData.message] : [...prev, eventData.message]
      })
    }

  }, [eventData])
  
  return (
    <div className={botStyle.ChatMainHolder}>
        <div className={botStyle.ConversationMessages}>
        {
          conversations.map((msgDetails, index) =>{
            return <MessageDisplayer
              key={index}
              message={msgDetails}
              IsIncoming ={
                msgDetails.sender_id === 0 ? true : false
              }
            />
          })
        }
        <div ref={messagesEndRef} />
        </div>
    </div>
  )
}

const InputField = ({ message, handleWritedMessage, inputRef }) => {
  const { t } = useTranslation();

  return (
    <input
      ref={inputRef}
      className={botStyle.inputMessage}
      onChange={(e) => handleWritedMessage(e)}
      type="text"
      value={message}
      placeholder={t('write a message ...')} 
    />
  );
};

const SendMessage = ({ message, setMessage }) => {
  const { userData } = useContext(UserContext);
  const {botSocket} = useContext(clientSocketContext)
  
  const handleSendMessage = () => {
    if (message.trim()) {
      const msgData = {
        sender_id: userData.user_id,
        receiver_id : 0,
        created_at :  new Date().toISOString(),
        content : message
      }
      botSocket.send(JSON.stringify({type: 'send_to_bot', message : msgData}))
      setMessage("");
    }
    // *********************************************************
  };
  return (
    <svg
      onClick={handleSendMessage}
      width="20"
      height="20"
      viewBox="0 0 23 25"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <path
        d="M22.286 0.243835C22.1378 0.115822 21.9576 0.0342628 21.7664 0.00866295C21.5753 -0.0169369 21.3811 0.0144765 21.2065 0.0992425L0.250977 10.3275V12.3067L9.05272 15.9678L14.6984 25H16.6021L22.617 1.32233C22.6658 1.12842 22.6606 0.924095 22.602 0.733153C22.5434 0.542212 22.4338 0.372516 22.286 0.243835ZM15.4268 23.1123L10.574 15.3485L18.0416 6.84337L16.86 5.72157L9.33401 14.293L2.07695 11.2744L20.7489 2.16046L15.4268 23.1123Z"
        fill="white"
        fillOpacity="0.5"
      />
    </svg>
  );
};

const ChatInput = () =>{
  const [message, setMessage] = useState("");
  const inputRef = useRef(null);

  function handleWritedMessage(e) {
    setMessage(e.target.value);
  }

  return (
    <div className={botStyle.ChatInputHolder}>
        <>
          <div className={botStyle.inputMainDiv}>
            <InputField inputRef={inputRef} message={message}
              handleWritedMessage={handleWritedMessage}
            />
              <SendMessage message={message} setMessage={setMessage} />
          </div>
        </>
    </div>
  );
}

const BotIcon = () => {
  const [convDisplay, setconvDisplay] = useState(false)
  
  const handleDisplayConv = () => {
    setconvDisplay(!convDisplay)
  }
  
  return (
    <Rnd default={{
      x : window.innerWidth  - (window.innerWidth * 0.2),
      y : window.innerHeight - (window.innerHeight * 0.2),
    }}>
    <div className={botStyle.botParentHolder}>
          <div style={{ display: convDisplay ? "grid" : "none" }} className={botStyle.conversationHolder}>
            <BotHeader/>
              <MainChat/>
            <ChatInput/>
          </div>
          <Lottie  animationData={botBody} className={botStyle.botbody} onDoubleClick={handleDisplayConv}/>
    </div>
    </Rnd>
  )
}

export default BotIcon