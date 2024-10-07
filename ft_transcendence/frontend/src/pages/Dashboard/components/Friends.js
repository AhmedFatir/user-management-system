import React from 'react'
import { useState, useEffect, useContext } from 'react'
import './friends.css'
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
import { useTranslation } from 'react-i18next'


const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

function Friends() {
  const {friendsStatus} = useContext(RealTimeContext);
  const [listFriend, setListFriend] = useState([]);
  const navigate = useNavigate();
  const {userFriends, userFriendsLoading} = useContext(UserContext)
  const { t } = useTranslation();
  // const {data ,isLoading, error} = useFetch(`${BACKEND_URL}/user/friends/list/`)
  // useEffect(() => {
  //   if (data) {
  //     setListFriend(data);
  //   }
  // }, [data]);
  
  function handleItemClick(list) {
    navigate(`/user/${list.username}`, {
      state: { userData: list },
    });
  }

  return (
    <div className='friendsContainer'>
      <div className='friendsBox'>
        <div className='headerFrends'>
          <h2>{t('FRIENDS')}</h2>
        </div>
        <div className='listFriends'>
          {userFriends && userFriends.length > 0 ? (
            userFriends.map((list) => (
              <div key={list.id} onClick={() => handleItemClick(list)}>
                <FriendsItem list={list} friendsStatus={friendsStatus}/>
              </div>
            ))
          ) : (
            <div className="ConversationContainerAnimation">
              <div className="NoOneToTalkTost"> <Lottie animationData={NoOneTotalkTo} /> </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
export default Friends