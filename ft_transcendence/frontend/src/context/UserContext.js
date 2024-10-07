import React, { createContext, useState, useEffect } from 'react';
import useFetch from '../hooks/useFetch';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
export const UserContext = createContext();

export const UserProvider = ({ children }) => {
    const [userData, setUserData] = useState(null);
    const [userDataLoading, setUserDataLoading] = useState(true);
    const [userAchievements, setUserAchievements] = useState(null);
    const [userAchievementsLoading, setUserAchievementsLoading] = useState(true);
    const [userFriends, setUserFriends] = useState(null);
    const [userFriendsLoading, setUserFriendsLoading] = useState(true);
    const [matchHistory, setMatchHistory] = useState(null);
    const [matchHistoryLoading, setMatchHistoryLoading] = useState(true);
    const [notifications, setNotifications] = useState(null);
    const [TounamentData, setTounamentData] = useState(null);
    const [TounamenrLoading, setTournamentLoading] = useState(true);
    const [blockedUsers, setBlockedUsers] = useState([]);

    const { data: globalStatsFetch, isLoading: globalStatsLoading, isError: globalStatsError } = useFetch(`${BACKEND_URL}/user/globalstats/`);

    useEffect(() => {
        if (globalStatsFetch) {
            const { player_stats, friends, notifications, game_history, achievements, tournament,  blocked_users} = globalStatsFetch;

            setUserData(player_stats);
            setUserDataLoading(false);

            setUserFriends(friends);
            setUserFriendsLoading(false);

            setNotifications(notifications);

            setMatchHistory(game_history);
            setMatchHistoryLoading(false);

            setUserAchievements(achievements);
            setUserAchievementsLoading(false);

            setTounamentData(tournament);
            setTournamentLoading(false);

            setBlockedUsers(blocked_users);
           
        }
    }, [globalStatsFetch]);

    const updateUserData = (newData) => {
        setUserData((prevData) => ({
            ...prevData,
            ...newData,
        }));
    };

    const updateUserAchievements = (newAchievements) => {
        setUserAchievements((prevAchievements) => ({
            ...prevAchievements,
            ...newAchievements,
        }));
    };

    const updateUserFriends = (newFriends) => {
        setUserFriends(newFriends);
    };

    const updatetounament = (newTournament) => {
        setTounamentData(newTournament);
    };

    const updateBlockedList = (newBlockedList) => {
        setBlockedUsers(newBlockedList);
    };

    const updateUserNotification = (newNotification) => {
        setNotifications(newNotification);
    };

    const updateMatchHistory = (newMatches) => {
        setMatchHistory((prevMatches) => ({
            ...prevMatches,
            ...newMatches,
        }));
    };
   
    return (
        <UserContext.Provider value={{
            userData, 
            userDataLoading, 
            globalStatsError, 
            userAchievements, 
            userAchievementsLoading, 
            userFriends,
            userFriendsLoading,
            matchHistory,
            matchHistoryLoading,
            notifications,
            TounamentData,
            TounamenrLoading,
            blockedUsers,
            updateUserData, 
            updateUserAchievements,
            updateUserFriends,
            updateMatchHistory,
            updateUserNotification,
            setNotifications,
            updatetounament,
            updateBlockedList,
        }}>
            {children}
        </UserContext.Provider>
    );
};
