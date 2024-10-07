import React, { useEffect, useState, useContext } from 'react'
import useFetch from '../../../../hooks/useFetch'
import './TournamentBracket.css'
import TournamentsItem from './TournamentsItem'
import Icon from '../../../../assets/Icon/icons'
import EightPlayer from '../../../../assets/TournamentEightPlayer'
// import FourPlayer from '../../../../assets/TournamentFourPlayers'
// import TwoPlayer from '../../../../assets/TournamentTwoPlayers'
import useAuth from '../../../../hooks/useAuth'
import TournamentPlayersItem from './TournamentPlayersItem'
import { CircularProgressbar, buildStyles } from 'react-circular-progressbar';
import 'react-circular-progressbar/dist/styles.css';
import { avatarsUnkown } from '../../../../assets/assets'
import { useTranslation } from 'react-i18next'
import { UserContext } from '../../../../context/UserContext'

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

function TournamentBracketOffline() {
  const { auth } = useAuth()
  const four_lines = new Array(4).fill(null);
  const two_lines = new Array(2).fill(null);
  const one_lines = new Array(1).fill(null);
  const { t } = useTranslation();
  const {TounamentData, TounamenrLoading} = useContext(UserContext)
  const [semiFinalMatches, setSemiFinalMatches] = useState([]);
  const [finalMatches, setFinalMatches] = useState([]);
  const [winner, setWinner] = useState()
  const {data: matches ,isLoading, error} = useFetch(`${BACKEND_URL}/user/local-tournament/${TounamentData.tournament_stage}`)

  const unknownAvatar = avatarsUnkown.img;

  
  const defaultSemiFInalMatches = [
    { id: 1, player1: {}, player2: {} },
    { id: 2, player1: {}, player2: {} },
  ];

  const defaultFinalMatches = [
    { id: 1, player1: {}, player2: {} },
  ];


  useEffect(() => {
    if (matches && matches.semiFinal && matches.semiFinal.length > 0) {
      const formattedSemiFinalMatches = matches.semiFinal.map(match => ({
        id: match.id,
        player1: match.player1,
        player2: match.player2,
        loosers: match.loosers || null,
        winner: match.winner || null,
        matchPlayed: match.matchPlayed,
        matchStage: match.matchStage,
      }));
  

      const formattedFinalMatches = matches.final && matches.final.length > 0
        ? matches.final.map(match => ({
            id: match.id,
            player1: match.player1,
            player2: match.player2,
            loosers: match.loosers || null,
            winner: match.winner || null,
            matchPlayed: match.matchPlayed,
            matchStage: match.matchStage,
          }))
        : []; 
        if (TounamentData.tournament_stage === "FINISHED"){
          setWinner(matches.final[0].winner.username);
        }
       
      setSemiFinalMatches(formattedSemiFinalMatches);
      setFinalMatches(formattedFinalMatches);
    } else {
      setSemiFinalMatches(defaultSemiFInalMatches);
      setFinalMatches(defaultFinalMatches);
    }
  }, [matches, TounamentData.tournament_stage]);

  const matchesToDisplayTwo = semiFinalMatches.length > 0 ? semiFinalMatches : defaultSemiFInalMatches;
  const matchesToDisplayOne = finalMatches.length > 0 ? finalMatches : defaultFinalMatches;


 
 
  return (
    <div className='bracket-container'>
        <div className="second-four-player">
            <div className="player-items">
                  {matchesToDisplayTwo.map((players) => (
                    <TournamentsItem key={players.id} players={players}/>
                  ))}
              </div>
              <div className="four-lines">
                  {two_lines.map((_, index) => (
                    <div className="two-lines" key={index}>
                      <div className="first-line"></div>
                    </div>
                  ))}
              </div>
              <div className="last-line">
                  {two_lines.map((_, index) => (
                    <div className="t-lines" key={index}>
                    </div>
                  ))}
              </div>
        </div>
        <div className="final-game-players">
              <div className="player-items">
                  {matchesToDisplayOne.map((players) => (
                    <TournamentsItem key={players.id} players={players}/>
                  ))}
              </div>
              <div className="final-lines">
                  {one_lines.map((_, index) => (
                    <div className="one-lines" key={index}>
                      <div className="first-line"></div>
                    </div>
                  ))}
              </div>
              <div className="last-line">
                  {one_lines.map((_, index) => (
                    <div className="t-lines" key={index}>
                    </div>
                  ))}
              </div>
        </div>
        <div className="winner-tounament">
         <Icon name='TournamentWin' className='tournament-win' />
        </div>
        <div className='TournamentPlayers'>
                <h2>{t('SEMI FINAL')}</h2>
            {matchesToDisplayTwo.map((players) => (
                    <TournamentPlayersItem key={players.id} players={players}/>
                  ))}
               <h2>{t('FINAL')}</h2>
            {matchesToDisplayOne.map((players) => (
                    <TournamentPlayersItem key={players.id} players={players}/>
                  ))}
              <div className='TournamentWinner'>
                <h2>{t('WINNER')}</h2>
                <div className='TheWinnerCard'>
                  <div className='WinnerImage'>
                    <img src={unknownAvatar}/>
                  </div>
                  <div className='WinerNameRank'>
                    <p>{winner}</p>
                    <p>{t('Rank')} : GOLD</p>
                  </div>
                  <div className='winerProgress'>
                          <CircularProgressbar
                                value={75}
                                text={`${75}%`}
                                styles={buildStyles({
                                    pathColor: '#F62943',
                                    textColor: '#F62943',
                                    trailColor: '#A9A6A6',
                                    backgroundColor: '#11141B',
                                })}
                            />
                            <CircularProgressbar
                                value={75}
                                text={`${75}%`}
                                styles={buildStyles({
                                    pathColor: '#F62943',
                                    textColor: '#F62943',
                                    trailColor: '#A9A6A6',
                                    backgroundColor: '#11141B',
                                })}
                            />
                            <CircularProgressbar
                                value={75}
                                text={`${75}%`}
                                styles={buildStyles({
                                    pathColor: '#F62943',
                                    textColor: '#F62943',
                                    trailColor: '#A9A6A6',
                                    backgroundColor: '#11141B',
                                })}
                            />
                  </div>
                </div>
              </div>
        </div>
        
    </div>
  )
}

export default TournamentBracketOffline