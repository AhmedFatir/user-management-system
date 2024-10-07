import React from 'react'
import { useState, useEffect, useContext } from 'react'
import './friendsMedia.css'
import History from '../../../assets/MatchHistoryData'
import FriendsItem from './FriendsItem'
import useFetch from '../../../hooks/useFetch'
import { useNavigate } from 'react-router-dom';
import Lottie from 'lottie-react'
import NoOneTotalkTo from '../../Chat/ChatAssets/NoOneTotalkTo.json'
import style from '../../Chat/Components/ContactSection/ContactSection.module.css'
import { RealTimeContext } from '../../../context/RealTimeProvider';
import RealTimeProvider from '../../../context/RealTimeProvider'
import { UserContext } from '../../../context/UserContext'
import FriendsItemMedia from './FriendsItemMedia'
import { useTranslation } from 'react-i18next'


const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

function FriendsMedia() {
  const {friendsStatus} = useContext(RealTimeContext);
  const [listFriend, setListFriend] = useState([]);
  const navigate = useNavigate();
  const { t } = useTranslation();
  const {userFriends, userFriendsLoading} = useContext(UserContext)
  
  function handleItemClick(list) {
    navigate(`/user/${list.username}`, {
      state: { userData: list },
    });
  }

  return (
    <div className='friendsContainerMedia'>
      <div className='friendsBoxMedia'>
        <div className='headerFrendMedia'>
          <h2>{t('FRIENDS')}</h2>
        </div>
        <div className='listFriendsMedia'>
          {userFriends && userFriends.length > 0 ? (
            userFriends.map((list) => (
              <div className='listFeiendListMedia' key={list.id} onClick={() => handleItemClick(list)}>
                <FriendsItemMedia list={list} friendsStatus={friendsStatus}/>
              </div>
            ))
          ) : (
            <div className="ConversationContainerAnimationMedia">
              <div className="NoOneToTalkTostMedia"> <Lottie animationData={NoOneTotalkTo} /> </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
export default FriendsMedia