import React, { useEffect, useContext } from 'react'
import { useState } from 'react'
import useFetch from '../../../../hooks/useFetch'
import './TournamentInfo.css'
import Icon from '../../../../assets/Icon/icons'
import { avatars }from '../../../../assets/assets'
import MainButton from '../../../../components/MainButton/MainButton'
import CreatTournamentPopUp from './CreatTournamentPopUp'
import JoinedTournament from './JoinedTournament'
import NoTournament from './NoTournament'
import Lottie from 'lottie-react'
import loadingAnimation from '../../../../components/OauthTwo/loading-animation.json'
import { UserContext } from '../../../../context/UserContext'

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;


const TournamentInfo = () => {
  const [joinedTournament, setJoinedTournament] = useState(false);
  const {TounamentData, TounamenrLoading} = useContext(UserContext)



  useEffect (() => {
    if (TounamentData && TounamentData.tournament_creator)
        setJoinedTournament(true)
    else
        setJoinedTournament(false)

  },[TounamentData])

  if (TounamenrLoading || !TounamentData){
    return (
      <div className='oauth-loading'>
        <Lottie animationData={loadingAnimation} style={{ width: 400, height: 400 }} />; 
      </div>
    )
  }

  return (
    <div className='overView-container'>
        {joinedTournament ? (
          <JoinedTournament TournamentData={TounamentData} />
        ) : (
          <NoTournament setJoinedTournament={setJoinedTournament}/>
        )}
    </div>
  )
}

export default TournamentInfo