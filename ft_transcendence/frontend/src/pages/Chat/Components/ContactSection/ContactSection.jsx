import React, { useState, useContext } from "react";
import style from "./ContactSection.module.css";
import SearchBar from "../SearchBar/SearchBar.jsx";
import { NotePencil } from "phosphor-react";
import NoOneTotalkTo from "../../ChatAssets/NoOneTotalkTo.json";
import Lottie from "lottie-react";
import { ChatListContext } from "../../Chat.jsx";
import { PickedConvContext } from "../../Chat.jsx";
import { CurrentUserContext } from "../../usehooks/ChatContext.js";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

const SendToNoneFriend = () => {
  function handleGlobalMessage() {
    alert("You touched Icon to send Message to GlobalUsers");
  }

  return (
    <NotePencil onClick={handleGlobalMessage} size={32}
                color="#ffffff" weight="light" />
  );
};

function LastMessageFormater(lastMessage) {
  if (lastMessage.length > 15) {
    return `${lastMessage.slice(0, 15)} ...`;
  }
  return lastMessage;
}

const ChatConversation = ({
  ConversationData,
  onSelectConversation,
}) => {

  const PickedUsername = useContext(PickedConvContext);

  function HandleClick() {
    onSelectConversation(ConversationData.username);
  }
  return (
    <div
      onClick={HandleClick}
      style={{
        borderRadius: "0.5rem",
        backgroundColor:
          PickedUsername === ConversationData.username ? "#11141B" : ""
      }}
    >
      <div className={style.ConversationHolder}>
        <img
          className={style.FriendPhoto}
          src={`${BACKEND_URL}` + ConversationData.avatar}
          alt="Your-friend-avatar"
        />

        <div className={style.NameAndLastMessage}>
          <p className={style.FriendName}> {ConversationData.username}</p>
          <p className={style.LastMessage}>
            {" "}
            {LastMessageFormater(ConversationData.lastMessage)}
          </p>
        </div>

        <div className={style.UnreadAndTime}>
          <p className={style.SendTime}> {ConversationData.lastTime}</p>
          {ConversationData.unreadMessages ? (
            <div className={style.unreadedMsgHolder}>
              <p className={style.UnreadMessages}>
                {" "}
                {ConversationData.unreadMessages >= 9
                  ? "+9"
                  : ConversationData.unreadMessages}
              </p>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
};

const ContactSection = ({handleConversationSelect }) => {
  const {ChatList} = useContext(ChatListContext);
  const [search, setSearch] = useState("");

  return (
    <div className={style.ContactSection}>
      <SearchBar search={search} setSearch={setSearch} />

      <div className={style.MessageNotePencilHolder}>
        <p className={style.MessageString}> Messages</p>
        <SendToNoneFriend />
      </div>

      {ChatList?.length ? (
        <div className={style.ConversationContainer}>
          {ChatList?.filter((userdata) => {
            return search.toLowerCase() === ""
              ? userdata
              : userdata.username
                  .toLowerCase()
                  .includes(search.toLowerCase().replace(/\s+/g, " "));
          }).map((DataObj, index) => {
            return (
              <ChatConversation
                key={index}
                ConversationData={DataObj}
                onSelectConversation={handleConversationSelect} //
              />
            );
          })}
        </div>
      ) : (
        <div className={style.ConversationContainerAnimation}>
          <div className={style.NoOneToTalkTost}>
            {" "}
            <Lottie animationData={NoOneTotalkTo} />{" "}
          </div>
        </div>
      )}
    </div>
  );
};

export default ContactSection;
