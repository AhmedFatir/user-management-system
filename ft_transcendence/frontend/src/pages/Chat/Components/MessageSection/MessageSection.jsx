import React, { useState, useRef, useContext, useEffect, } from "react";
import styles from "./MessageSection.module.css";
import EmptyChatAnimation from "../../ChatAssets/EmptyChatAnimation.json";
import online from "../../ChatAssets/online.json";
import offline from "../../ChatAssets/offline.json";
import NoPickedConv from "../../ChatAssets/NoConversationchoiced.json";
import { Smiley, Image , Gear, Trash } from "phosphor-react";
import Lottie from "lottie-react";
import data from "@emoji-mart/data";
import Picker from "@emoji-mart/react";
import { conversationMsgContext } from "../../Chat.jsx";
import { ChatListContext } from "../../Chat.jsx";
import { PickedConvContext } from "../../Chat.jsx";
import { CurrentUserContext } from "../../usehooks/ChatContext.js";
import { clientSocketContext } from "../../usehooks/ChatContext.js";
import { chatPartnerContext } from "../../Chat.jsx";
import notificationSound from "../../ChatAssets/notification.mp3";
import BlockPopUps from "../BlockPopUps/BlockPopUps.jsx";
import { TypingContext } from "../../Chat.jsx";
import typinganimation from "../../ChatAssets/lastTyping.json"
import { ErrorToast } from "../../../../components/ReactToastify/ErrorToast.js";
import { useTranslation } from 'react-i18next'



const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

const ImportItem = ({ setImportClicked }) => {
  return (
    <svg
      onClick={() => setImportClicked((prev) => !prev)}
      className={styles.ImportButton}
      width="30"
      height="30"
      viewBox="0 0 23 23"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <path
        d="M11.1996 0C5.02861 0 0 5.1635 0 11.5C0 17.8365 5.02861 23 11.1996 23C17.3706 23 22.3992 17.8365 22.3992 11.5C22.3992 5.1635 17.3706 0 11.1996 0ZM15.6794 12.3625H12.0395V16.1C12.0395 16.5715 11.6588 16.9625 11.1996 16.9625C10.7404 16.9625 10.3596 16.5715 10.3596 16.1V12.3625H6.71975C6.26057 12.3625 5.87978 11.9715 5.87978 11.5C5.87978 11.0285 6.26057 10.6375 6.71975 10.6375H10.3596V6.9C10.3596 6.4285 10.7404 6.0375 11.1996 6.0375C11.6588 6.0375 12.0395 6.4285 12.0395 6.9V10.6375H15.6794C16.1386 10.6375 16.5194 11.0285 16.5194 11.5C16.5194 11.9715 16.1386 12.3625 15.6794 12.3625Z"
        fill="white"
        fillOpacity="0.5"
      />
    </svg>
  );
};

function reformeDate(datestr) {
  const datetimeObj = new Date(datestr);
  const hours = datetimeObj.getHours();
  const minutes = String(datetimeObj.getMinutes()).padStart(2, "0"); // Convert to string first
  return `${hours}:${minutes}`;
}

/*ADD props to args Here*/
const SendMessage = ({ message, setMessage ,CurrentUser, ChatPartner, clientSocket, handleSendMessage}) => {
  let typingTimeoutId = null; //Pay Attention to this fucking 0

  useEffect(() =>{
  const messageData = {
      sender_id    : CurrentUser?.user_id,
      receiver_id  : ChatPartner?.id
    }
    if (message.length && message.length % 2 === 0){
        clientSocket?.send(JSON.stringify({type: "typing_event", messageData: messageData}))
      // ********* 4 seconds Logic********************************************************************************
          if (typingTimeoutId !== null) {                                                                             
            clearTimeout(typingTimeoutId);
          }
          typingTimeoutId = setTimeout(() => {
            clientSocket?.send(JSON.stringify({ type: "deactivate_typing_event", messageData: messageData }));
            }, 5000);
      // ***********************************************************************************************************
    }
      if (message.length === 0){
      clientSocket?.send(JSON.stringify({type: "deactivate_typing_event", messageData: messageData}))
      clearTimeout(typingTimeoutId);
      typingTimeoutId = null;
  }
  
}, [message])

  return (
    <svg
      onClick={handleSendMessage}
      width="30"
      height="30"
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
/***********************STOOOOOP */
const Emojies = ({ SetPicker }) => {
  return (
    <Smiley
      onClick={() => SetPicker((prev) => !prev)}
      className={styles.Emojie}
      size={40}
      color="#242424"
      weight="fill"
    />
  );
};

const InputField = ({ message, handleWritedMessage, inputRef, handleSendMessage }) => {
  const { t } = useTranslation();

  return (
    <input
      ref={inputRef}
      className={styles.inputMessage}
      onChange={(e) => handleWritedMessage(e)}
      onKeyDown={(e) => handleSendMessage(e)}
      type="text"
      value={message}
      placeholder={t('write a message ...')} 

    />
  );
};

const ChatHeader = () => {
  const {ChatPartner: ChatPartnerData} = useContext(chatPartnerContext);
  const { t } = useTranslation();

  function handleParamsClick() {
    alert("Olaaala");
  }

  return (
    <div className={styles.ChatHeaderHolder}>
      {ChatPartnerData ? (
        <>
          <div className={styles.UserInfo}>
            <img
              className={styles.FriendPhoto}
              src={`${BACKEND_URL}${ChatPartnerData?.avatar}`}
              alt="Your-friend-avatar"
            />
            <div className={styles.FriendNameAndStatus}>
              <div className={styles.FriendName}> {ChatPartnerData?.username} </div>
              <div className={styles.StatusHolder}>
                <div className={styles.StatusIcon}>
                  {" "}
                  <Lottie animationData={ChatPartnerData?.status ? online : offline} />
                </div>
                <div className={styles.Status}>
                  {" "}
                  {ChatPartnerData?.status ? t("Online") : t("Offline")}
                </div>
              </div>
            </div>
          </div>
          <div className={styles.ChatSettings}>
            {" "}
            <Gear onClick={handleParamsClick}
              size={32}
              color=" #8D93AC"
            />{" "}
          </div>
        </>
      ) : null}
    </div>
  );
};

const ChatInput = ({selectedImage, setSelectedImage}) => {
  const CurrentUser = useContext(CurrentUserContext);
  const {ChatPartner} = useContext(chatPartnerContext);
  const {stateValue: clientSocket} = useContext(clientSocketContext);
  const Pickerusername = useContext(PickedConvContext);
  const [PickerClick, SetPicker] = useState(false);
  const [ImportItemsClicked, setImportClicked] = useState(false);
  const [message, setMessage] = useState("");
  const inputRef = useRef(null);

  function handleWritedMessage(e) {
    setMessage(e.target.value);
  }

  function handleEmojieSelect(e) {
    const CursorPos = getCursorPosition();
    const start = message.substring(0, CursorPos);
    const end = message.substring(CursorPos);
    const NewMessage = start + e.native + end;
    setMessage(NewMessage);
  }

  const getCursorPosition = () => {
    if (inputRef.current) {
      return inputRef.current.selectionStart;
    }
    return -1;
  };

  const handleImageSelect = (event) => {
    try{
      setSelectedImage(null);
      const file = event.target.files[0];
      const reader = new FileReader();
    
      reader.onloadend = () => {
        setSelectedImage(reader.result);
      };
      if (file) {
        reader.readAsDataURL(file);
      } else {
        setSelectedImage(null);
      }
    } catch(e){
      ErrorToast('can\'t Load Image');
    }
    };

    const handleSendMessage = (event) => {
      if (event.type === 'keydown' && event.key !== 'Enter')
          return ;
      if (message.trim() || selectedImage) {

        SetPicker((prev) => (prev ? !prev : prev));//deactivate emojies palett when - sending msg !
        const messageData = {
          sender_id: CurrentUser?.user_id,
          receiver_id: ChatPartner?.id,
          seen: false,
        };
        // try to send message only
        if (message.trim() && !selectedImage){
          messageData.msgType = 'text';
          messageData.content = message;
          setMessage("");
        }
        // try to send image
        else if (!message.trim() && selectedImage){
          messageData.msgType = 'image';
          messageData.ImgPath=selectedImage
          setSelectedImage(null)
        }
        if (!(message.trim() && selectedImage)){
            clientSocket?.send(JSON.stringify({type: 'newchat.message', messageData: messageData}));
            const notif = new Audio(notificationSound);
            notif.play();
        }
      }
    };

  return (
    <div className={styles.ChatInputHolder}>
      {Pickerusername.length ? (
        <>
          <BlockPopUps/>
          <div className={styles.ImportOptions}
            style={{ display: ImportItemsClicked ? "flex" : "none" }}
          >
            <div className={styles.ImageBack}>
              <label htmlFor="uploadImagebtn">
                <Image className={styles.ImportImage} size={40} />{" "}
              </label>
              <input
                type="file"
                name="chat-photo"
                id="uploadImagebtn"
                className="upload-input"
                onChange={handleImageSelect}
                accept="image/*"
              />
            </div>
          </div>

          <div className={styles.inputMainDiv}>
            <ImportItem setImportClicked={setImportClicked} />
            <InputField inputRef={inputRef} message={message} handleWritedMessage={handleWritedMessage} handleSendMessage ={handleSendMessage} />
            <Emojies SetPicker={SetPicker} />
            <SendMessage message={message} setMessage={setMessage} CurrentUser={CurrentUser}
                         ChatPartner={ChatPartner} clientSocket={clientSocket} handleSendMessage={handleSendMessage}/>
          </div>

          <div
            style={{ display: PickerClick ? "inline" : "none" }}
            className={styles.EmojiPicker}
          >
            <Picker
              theme="dark"
              data={data}
              onEmojiSelect={handleEmojieSelect}
            />
          </div>
        </>
      ) : null}
    </div>
  );
};

const MessageDisplayer = ({ message, IsIncoming }) => {
  const CurrentUser = useContext(CurrentUserContext);
  const {ChatPartner} = useContext(chatPartnerContext);

  return (
    <div className={IsIncoming ? styles.MsgIncom : styles.MsgOut}>
      <div className={IsIncoming ? styles.receiverAvatar : styles.MyAvatar}>
        <img
          className={styles.avatar}
          src={
            IsIncoming
              ? `${BACKEND_URL}` + ChatPartner?.avatar //Here is the shit added target receiver Here !
              : `${BACKEND_URL}` + CurrentUser?.avatar
          }
          alt="user-avatar"
        />
      </div>

      <div className={styles.msgContent}>
        <div className={IsIncoming ? styles.incoming : styles.outgoing}>
          {
            message.msgType === 'text' ? message.content : <img width="200" height="200" style={{borderRadius : '18px'}} src={`${BACKEND_URL}${message.ImgPath}`} alt="messagePhoto" /> 
          }
        </div>
        <h1 className={IsIncoming ? styles.SendingTime : styles.SendingTimeout}>
          {reformeDate(message.created_at)}
        </h1>
      </div>
    </div>
  );
};

const Typing =() => {
  const {ChatPartner} = useContext(chatPartnerContext);

  return (
    <div className={styles.MsgIncom}>
        <div className={styles.receiverAvatar}>
        <img
          className={styles.avatar}
          src={ `${BACKEND_URL}` + ChatPartner?.avatar //Here is the shit added target receiver Here !
          }
          alt="user-avatar"
        />
      </div>

      <div className={styles.msgContentanimation}>
        <div className={styles.typingholder}>
          <Lottie animationData={typinganimation}/>
        </div>
        <h1 className={styles.SendingTime}> now </h1>
      </div>

    </div>
  )
}

const ChatMainHolder = ({selectedImage, setSelectedImage}) => {
  const Pickedusername = useContext(PickedConvContext);
  const conversationMsg = useContext(conversationMsgContext);
  const messagesEndRef = useRef(null);
  const CurrentUser = useContext(CurrentUserContext);
  const {status} = useContext(TypingContext)
  const { t } = useTranslation();


  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };
  const handleCloseImg = () =>{
    setSelectedImage(null);
  }

  useEffect(() => {
    scrollToBottom();
  }, [conversationMsg, status]);

  return (
    <div className={styles.ChatMainHolder}>
      {Pickedusername.length ? (
        <>
        <div className={styles.ConversationMessages}>
          {conversationMsg?.map((elem, index) => {
            return (
              <MessageDisplayer
                key={index}
                message={elem}
                IsIncoming={
                  elem.receiver_id === CurrentUser?.user_id ? true : false
                }
              />
            );
          })}
          <div ref={messagesEndRef} />
          { status ? <Typing/> : null }
        </div>
        {
          // Display Selected Img
            selectedImage && (
              <div className={styles.UserSelectedImgHolder}>
                <img className={styles.UserSelectedImg} src={selectedImage} alt="Selected" />
                <div className={styles.EraseSelectedImgHolder}>
                  <Trash size={40} className={styles.EraseSelectedImg} onClick={handleCloseImg} color="#F62943" />
                </div>

              </div>
        )}
        </>
      ) : (
        <div className={styles.StartMessageHolder}>
          <div className={styles.NoPickedConvContainer}>
            {" "}
            <Lottie animationData={NoPickedConv} />{" "}
          </div>
          <div className={styles.QuoteContainer}>
            <blockquote className={styles.GoPickConversation}>
              {" "}
              {t("Another Conversation Another World")}{" "}
            </blockquote>
          </div>
        </div>
      )}
    </div>
  );
};

const MessageSection = () => {
  const {ChatList} = useContext(ChatListContext);
  const PickedUsername = useContext(PickedConvContext);
  const {setChatPartner} = useContext(chatPartnerContext)
  const [selectedImage, setSelectedImage] = useState(null);
  const { t } = useTranslation();



  useEffect(() => {
  
    setChatPartner(ChatList?.filter((elem) => elem.username === PickedUsername )[0]);
  
  }, [ChatList, PickedUsername]); // Dependencies

  return (
    <>
      {!ChatList?.length ? (
        <div className={styles.MessageSection}>
          <div className={styles.WelcomeChat}>
            <div className={styles.Animationstyles}>
              {" "}
              <Lottie animationData={EmptyChatAnimation} />
            </div>
            <blockquote className={styles.ChatQuote}>
              {" "}
              {t("Unleash the power of connection!")} <br />
              {t("Start chatting and discover what")}{" "}
              <span className={styles.Clunca}>Clunca </span> {t("has to offer you.")}{" "}
            </blockquote>
          </div>
        </div>
      ) : (
        <div className={styles.MessageSectionFull}>
            <ChatHeader />
            <ChatMainHolder selectedImage={selectedImage} setSelectedImage={setSelectedImage}/>
            <ChatInput selectedImage={selectedImage} setSelectedImage={setSelectedImage}/>
        </div>
      )}
    </>
  );
};

export default MessageSection;
