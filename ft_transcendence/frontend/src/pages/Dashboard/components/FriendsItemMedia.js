import React, { useEffect, useState } from 'react'
import './friendsItemMedia.css'
import Lottie from 'lottie-react';
import online from '../../Chat/ChatAssets/online.json'
import offline from '../../Chat/ChatAssets/offline.json'


const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

function FriendsItemMedia({list, friendsStatus}) {
  const [isonline, setOnline] = useState(false);


  useEffect(() => {
    if (typeof friendsStatus === 'object' && friendsStatus !== null) {
      const friendStatus = friendsStatus[list.id];

      if (friendStatus) {
        setOnline(friendStatus === 'online');
      } else {
        if (list.is_online)
          setOnline(true)
        else
          setOnline(false)
      }
    }
    else{
      if (list.is_online)
        setOnline(true)
      else
        setOnline(false)

    }
    if (list.is_online)
        setOnline(true)
  }, [friendsStatus, list.id]);



  return (
    <div className='listFriendCardMedia'>
       <div className='firendImageMedia'>
          <img src={`${BACKEND_URL}${list.avatar}`}
          style={{ filter: isonline ? 'none' : 'grayscale(100%)' }}/>
           <div className='FriendStatusMedia'>
              {isonline ? <div className="statusOnlineMedia"> <Lottie animationData={online} /></div> : 
              <div className="statusOnlineMedia"> <Lottie animationData={offline} /></div>}
          </div>
       </div>
       <div className='FriendNameRandMedia'>
            <div className='FriendNameMedia'>
                <p>{list.username}</p>
            </div>
      
       </div>
    </div>
  )
}

export default FriendsItemMedia