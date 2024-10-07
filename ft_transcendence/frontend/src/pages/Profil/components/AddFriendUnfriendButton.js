import React, { useState, useEffect, useContext } from 'react'
import useAuth from '../../../hooks/useAuth';
import Icon from '../../../assets/Icon/icons'
import { InfoToast } from '../../../components/ReactToastify/InfoToast'
import { ErrorToast } from '../../../components/ReactToastify/ErrorToast'
import { SuccessToast } from '../../../components/ReactToastify/SuccessToast'
import { UserContext } from '../../../context/UserContext';
import { ProfileContext } from '../../../context/ProfilContext';
import { useTranslation } from 'react-i18next';


const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

function AddFriendUnfriendButton({ FriendId }) {
    const { auth }  = useAuth()
    const {updateUserFriends} = useContext(UserContext)
    const {isBlockedMe, isBlockingHim, isRequest, setIsRequst} = useContext(ProfileContext)
    const { t } = useTranslation();
    const isDisabled = isBlockingHim || isBlockedMe;
 
   
    const handleAddFriend = async () => {
        try {
            const response = await fetch(`${BACKEND_URL}/user/friends-request/${FriendId}/`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${auth.accessToken}`,
            },
            body: JSON.stringify({})
            });

            if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'An error occurred while sending the friend request.');
            }

            const data = await response.json();
            setIsRequst('Friend request sent.');

        } catch (error) {
            ErrorToast(error.message);
            // alert(error.message);
        }
    };

    const handleCancelRequest = async () => {
        try {
            const response = await fetch(`${BACKEND_URL}/user/friends-request/${FriendId}/`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${auth.accessToken}`,
            },
            body: JSON.stringify({})
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'An error occurred while sending the friend request.');
            }

            const data = await response.json();
            setIsRequst(data.message);

        } catch (error) {
            ErrorToast(error.message);
            // alert(error.message);
        }
    };

    const handleUnfriend = async () => {
        try {
            const response = await fetch(`${BACKEND_URL}/user/friend/${FriendId}/`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${auth.accessToken}`,
                },
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'An error occurred while unfriending the user.');
            }

            const data = await response.json();
            setIsRequst(data.message);
            const friendsResponse = await fetch(`${BACKEND_URL}/user/friends/list/`, {
                method: 'GET',
                    headers: {
                      'Content-Type': 'application/json',
                      'Authorization': `Bearer ${auth.accessToken}`
                    }
                  });
                  
                  if (!friendsResponse.ok) {
                    throw new Error('Network response was not ok');
                  }
                  
                  const updatedFriendsData = await friendsResponse.json();
            
                updateUserFriends(updatedFriendsData);

        } catch (error) {
            ErrorToast(error.message);
            // alert(error.message);
        }
    };
    

    const handleRejectRequest = async () => {
        try {
            const response = await fetch(`${BACKEND_URL}/user/friends-request/${FriendId}/response/`, {
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${auth.accessToken}`,
                },
                body: JSON.stringify({ 'status' : 'reject' })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'An error occurred while unfriending the user.');
            }
            const data = await response.json();
            setIsRequst('Friend request does not exist.');

        } catch (error) {
            ErrorToast(error.message);
            // alert(error.message);
        }
      };

    const getButtonAction = () => {
        switch (isRequest) {
          case 'Friend request does not exist.':
            return { text: t('Add Friend'), action: handleAddFriend };
          case 'Friend request sent.':
            return { text: t('Cancel Request'), action: handleCancelRequest };
          case 'Friend request received.':
            return { text: t('Reject Request'), action: handleRejectRequest };
          case 'Friends':
            return { text: t('Unfriend'), action: handleUnfriend };
          default:
            return { text: t('Add Friend'), action: handleAddFriend };
        }
      };

    const { text, action } = getButtonAction();

    return (
        <div className={`AddFriend-button  profil-button ${isDisabled ? 'disabled' : ''}`} onClick={action}>
            <Icon name='AddFriend' className='Add-Friend profil-icon' />
            <p>{text}</p>
        </div>
    )
}

export default AddFriendUnfriendButton