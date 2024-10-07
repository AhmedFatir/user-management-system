import React, { createContext, useState, useEffect } from 'react';
import useFetch from '../hooks/useFetch';
import useAuth from '../hooks/useAuth';
import Lottie from 'lottie-react';
import loadingAnimation from '../components/OauthTwo/loading-animation.json'
import { useParams } from 'react-router-dom';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
export const ProfileContext = createContext();

export const ProfileProvider = ({ children, userId }) => {
    const { auth }  = useAuth()
    const [profilData, setProfileData] = useState(null);
    const [profileDataLoading, setProfileDataLoading] = useState(true);
    const [profileBlockLoading, setProfileBockLoading] = useState(true);
    const [profileFriendLoading, setProfileFriendLoading] = useState(true);
    const [profileAchievements, setProfileAchievements] = useState(null);
    const [profileAchievementsLoading, setProfileAchievementsLoading] = useState(true);
    const [profileFriends, setProfileFriends] = useState(null);
    const [profileFriendsLoading, setProfileFriendsLoading] = useState(true);
    const [profileMatchHistory, setProfileMatchHistory] = useState(null);
    const [profileMatchHistoryLoading, setProfileMatchHistoryLoading] = useState(true);
    const [profilisBlocked, setIsBlocked] = useState(false);
    const [isBlockedMe, setIsBlockedMe] = useState(false);
    const [isBlockingHim, setIsBlocking] = useState(false); 
    const [isRequest, setIsRequst] = useState(null)
    const [history, setHistory] = useState(null);
    const [HistoryLoading, setHistoryLoading] = useState(true);


    const { nameOfUser } = useParams();
    const [isProfileDataReady, setIsProfileDataReady] = useState(false); 



    useEffect(() => {
        const fetchProfileData = async () => {
            if (!nameOfUser) {
                console.warn("nameOfUser is undefined, skipping fetch.");
                setIsProfileDataReady(true);
                return;
            }
            const url = `${BACKEND_URL}/user/stats/username/${nameOfUser}`;
            try {
                const response = await fetch(url, {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${auth.accessToken}`,
                    },
                });
                if (response.ok) {
                    const data = await response.json();
                    setProfileData(data);
                    setIsBlockedMe(data.is_blocked);
                    setIsBlocking(data.is_blocking);
                  

                } else {
                    console.error('Error fetching profile data:', response.statusText);
                }
            } catch (error) {
                console.error('Error fetching profile data:', error);
            } finally {
                setProfileDataLoading(false);
            }
        };

        fetchProfileData();
    }, [nameOfUser, auth.accessToken]);

    useEffect(() => {
        const fetchRequestStatus = async () => {
            if (!profilData) return;
            const url = `${BACKEND_URL}/user/friends-request/${profilData.user_id}/`;
            try {
                const response = await fetch(url, {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${auth.accessToken}`,
                    },
                });
                if (response.ok) {
                    const data = await response.json();
                    setIsRequst(data.message)
          
                } else {
                    console.error('Error fetching block status:', response.statusText);
                }
            } catch (error) {
                console.error('Error fetching block status:', error);
            }finally {
                setProfileFriendLoading(false);
            }
        };

        fetchRequestStatus();
    }, [profilData]);

    useEffect(() => {
        const fetchBlockStatus = async () => {
            if (!profilData) return;
            const url = `${BACKEND_URL}/user/${profilData.user_id}/block-unblock/`;
            try {
                const response = await fetch(url, {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${auth.accessToken}`,
                    },
                });
                if (response.ok) {
                    const data = await response.json();
                    setIsBlocked(data.is_blocked);
                } else {
                    console.error('Error fetching block status:', response.statusText);
                }
            } catch (error) {
                console.error('Error fetching block status:', error);
            }
            finally {
                setProfileBockLoading(false);
            }
        };
        
        fetchBlockStatus();
    }, [profilData, auth.accessToken]);

    useEffect(() => {
        const fetchGameHistory = async () => {
            if (!profilData) return;
            const url = `${BACKEND_URL}/api/game/game-history/${profilData.user_id}`;
            try {
                const response = await fetch(url, {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${auth.accessToken}`,
                    },
                });
                if (response.ok) {
                    const data = await response.json();
                    setHistory(data);
                } else {
                    console.error('Error fetching block status:', response.statusText);
                }
            } catch (error) {
                console.error('Error fetching block status:', error);
            }
            finally {
                setHistoryLoading(false);
            }
        };
        
        fetchGameHistory();
    }, [profilData, auth.accessToken]);
  
    useEffect(() => {
        console.log(profileDataLoading, profileBlockLoading,profileFriendLoading, HistoryLoading)
        if (!profileDataLoading && !profileBlockLoading && !profileFriendLoading && !HistoryLoading) {
            setIsProfileDataReady(true);
        }
   
    }, [profileDataLoading, profileBlockLoading, profileFriendLoading, HistoryLoading]);

    if (!isProfileDataReady) {
        return (
            <div className='oauth-loading'>
                <Lottie animationData={loadingAnimation} style={{ width: 400, height: 400 }} />; 
            </div>
        )
            
    }
    return (
        <ProfileContext.Provider value={{
            profilData,
            profileAchievements,
            profileFriends,
            profileMatchHistory,
            profilisBlocked,
            isBlockedMe,
            isBlockingHim,
            isRequest,
            history,
            setIsBlocked,
            setIsBlockedMe,
            setIsBlocking,
            setIsRequst,

    

        }}>
            {children}
        </ProfileContext.Provider>
    );
};
