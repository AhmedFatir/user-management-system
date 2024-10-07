import React from 'react'
import { useState } from 'react';
import CreatTournamentPopUp from './CreatTournamentPopUp'
import Lottie from 'lottie-react';
import './noTournament.css'
import MainButton from '../../../../components/MainButton/MainButton';
import popularTournaments from '../../../../assets/tournament';
import PopularTournaments from './PopularTournaments';
import sadFace from '../../../../assets/sadFace.json'
import { useTranslation } from 'react-i18next'


function NoTournament({setJoinedTournament}) {
    const [modalCreat, setModalCreat] = useState(false);
    const tounemrntExist = true
    const { t } = useTranslation();


      

    const handleCreatTournament = () => {
        setModalCreat(true);
    }

    const handleClosePopup = () => {
        setModalCreat(false)
    }
  return (
    <div className="no-tournament">
        <div className="tournament-page">
            {tounemrntExist &&
            <h2>{t('Popular Tournaments')}</h2>
            }
            <div className="examples-section">
                {tounemrntExist ? 
                (popularTournaments.map((tounament) => (
                    <PopularTournaments key={tounament.id} tounament={tounament}/>
                    )))
                : (
                    <div className='sadFaceAnimation'>
                         <div className='sadFace'><Lottie animationData={sadFace} /> </div>
                        <h2>{t('No tournaments available at the moment')}</h2>
                    </div>
                )}
            </div>
        </div>
        <div className='CreatYourTournament'>
            
            <div className='StartedTournamentButton'>

                <MainButton type="submit" functionHandler={handleCreatTournament} content="Creat Tounament"/>
                {/* <button onClick={handleCreatTournament}>Creat Tournament</button> */}
                </div>
                <CreatTournamentPopUp isOpen={modalCreat} onClose={handleClosePopup} setJoinedTournament={setJoinedTournament}/>
        </div>
    </div>
  )
}

export default NoTournament