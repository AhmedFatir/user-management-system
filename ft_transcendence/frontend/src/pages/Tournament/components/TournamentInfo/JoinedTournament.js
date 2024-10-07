import React from 'react'
import { useState, useEffect, useContext } from 'react'
import useAuth from '../../../../hooks/useAuth'
import useFetch from '../../../../hooks/useFetch'
import Icon from '../../../../assets/Icon/icons'
import { avatars } from '../../../../assets/assets'
import './joinedTournament.css'
import { CircularProgressbar, buildStyles } from 'react-circular-progressbar';
import 'react-circular-progressbar/dist/styles.css';
import MainButton from '../../../../components/MainButton/MainButton'
import { UserContext } from '../../../../context/UserContext'
import { useTranslation } from 'react-i18next'
import JoinedTournamentOnline from './JoinedTournamentOnline'
import JoinedTournamentOffline from './JoinedTournamentOffline'


const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;


function JoinedTournament({TournamentData}) {
    const [isOnline, setIsOnline] = useState(false);

    useEffect(() => {
        setIsOnline(TournamentData.is_online);
      }, [TournamentData.is_online]);

  return (
    <div className="joined-tournament">
      {isOnline ? (
        <JoinedTournamentOnline TournamentData={TournamentData}/>
      ) : (
        <JoinedTournamentOffline TournamentData={TournamentData}/>
      )}
    </div>
  )
}

export default JoinedTournament