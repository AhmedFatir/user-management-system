import React from 'react'
import { useState, useEffect, useContext } from 'react'
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
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
import './joinedTournamentOffline.css'
import { avatarsUnkown } from '../../../../assets/assets'

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;


function JoinedTournamentOffline({TournamentData}) {
    const { auth }  = useAuth()
    const [joinedOwner, setjoinedOwner] = useState(false);
    const [profilData, setProfilData] = useState([]);
    const {userData, updatetounament} = useContext(UserContext)
    const [progress, setProgress] = useState(0);
    const [Finishid, setIsFinished] = useState(false)
    const [winner, setWinner] = useState();
    const { t } = useTranslation();
    const unknownAvatar = avatarsUnkown.img;
    const navigate = useNavigate();
    const [matchToDisplay, setMatchToDisplay] = useState(null);
    const {data: matches ,isLoading: matchesisLoading, error: matchesError} = useFetch(`${BACKEND_URL}/user/local-tournament/${TournamentData.tournament_stage}`)
  

    useEffect(() => {
        if (matches && matches.semiFinal) {
          const semiFinalMatches = matches.semiFinal;
      

          if (!semiFinalMatches[0]?.matchPlayed) {
            setMatchToDisplay(semiFinalMatches[0]);
          } 

          else if (!semiFinalMatches[1]?.matchPlayed) {
            setMatchToDisplay(semiFinalMatches[1]);
          } 
   
          else if (matches.final && matches.final.length > 0 && !matches.final[0]?.matchPlayed) {
            setMatchToDisplay(matches.final[0]);
          }
          if (TournamentData.tournament_stage === "FINISHED"){
            setIsFinished(true)
            setWinner(matches.final[0].winner.username);
          }
        }
      }, [matches]);


    const date = new Date(TournamentData.created_at);
    const {data ,isLoading, error} = useFetch(`${BACKEND_URL}/user/stats/${TournamentData.tournament_creator}`)

    useEffect(() => {
        if (userData.user_id === TournamentData.tournament_creator)
            setjoinedOwner(true)
    },[userData]);

    const formattedDate = date.toLocaleDateString('en-GB', {
        day: '2-digit',
        month: 'short',
    });

    const formattedTime = date.toLocaleTimeString('en-GB', {
        hour: '2-digit',
        minute: '2-digit',
    });

    useEffect(() => {
        if (data) {
          setProfilData(data);
        }
      }, [data]);
      

      useEffect(() => {
        setTimeout(() => {
          setProgress(profilData.rank_progress);
        }, 500); 
      }, []);
  
      const handleStartTournament = async () => {
        const gameRoomResponse = await axios.post(
            `${BACKEND_URL}/api/game/create-local-game-room/`,
            { 
                player1: matchToDisplay.player1.id,
                player2: matchToDisplay.player2.id,
                arena: 'hell',
            },
            {
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${auth.accessToken}`
                }
            }
        );

        const gameRoomId = gameRoomResponse.data.id;
        navigate('/local-tournament-game', { state: { gameRoomId: gameRoomId , tournamentId: matchToDisplay.id } }, { replace: true });
      }

      const handleDeleteTournament = async () => {
        try {
          const response = await fetch(`${BACKEND_URL}/user/local-tournament/`, {
            method: 'DELETE',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${auth.accessToken}`

            },
          });
      
          if (response.ok) {
            const data = await response.json();
            const TournamentResponse = await fetch(`${BACKEND_URL}/user/local-tournament/`, {
                method: 'GET',
                    headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${auth.accessToken}`
                    }
                });
                if (TournamentResponse.status === 404) {
                    updatetounament([])
    
                } else if (TournamentResponse.ok) {
                    const updatedTournamentData = await TournamentResponse.json();
                    updatetounament(updatedTournamentData);
                } else {
                    throw new Error('Network response was not ok');
                }
            console.log('Tournament deleted successfully:', data);
    
          } else {
            const errorData = await response.json();
            console.error('Failed to delete tournament:', errorData);

          }
        } catch (error) {
          console.error('Error deleting tournament:', error);
   
        }
      };
      
  return (
    <div className="joined-tournament">
       <h1 className='tournament-title'>{TournamentData.tournament_name}OFFLINE</h1>
       
       <div className={`tournament-info-container ${TournamentData.tournament_map}`}>
            <div className='tournament-info-item'>
                <Icon name='chump_cup' className="tournament-info-icon"/>
                <div className='tournament-info-item-txt'>
                    <p>{TournamentData.tournament_prize}</p>
                    <span>{t('Total Prize Pool')}</span>
                </div>
            </div>
            <div className='tournament-info-item'>
                <Icon name='calendar' className="tournament-info-icon"/>
                <div className='tournament-info-item-txt'>
                    <p>{`${formattedDate} ${formattedTime}`}</p>
                    <span>{t('Tournament Start')}</span>
                </div>
            </div>
            <div className='tournament-info-item'>
                <Icon name='game_mode' className="tournament-info-icon"/>
                <div className='tournament-info-item-txt'>
                    <p>{t('Game Mode')}</p>
                    <span>Offline</span>
                </div>
            </div>
            <div className='tournament-info-item'>
                <Icon name='location' className="tournament-info-icon"/>
                <div className='tournament-info-item-txt'>
                    <p>{t('Map')}</p>
                    <span>{TournamentData.tournament_map}</span>
                </div>
            </div>
            <div className='tournament-subscribers'>
                <div className='tournament-subscribers-avatars'>
                {TournamentData.tournament_participants && TournamentData.tournament_participants.map((player, index) => (
                    <img key={index} className={`image${index + 1}`} src={`${BACKEND_URL}${player.avatar}`} alt={`Player ${index + 1}`} />
               
                ))}
                </div>
                <span className='tournament-subscribers-counter'>
                    {TournamentData.tournament_participants && TournamentData.tournament_participants.length}/4 Joined
                </span>
            </div>
        </div>
        <div className='tournament-desc'>
            <div className='tournament-desc-rules'>
                <div className='tournament-desc-rules-top'>
                    <h1>{t('Attention Pongers')}</h1>
                    <p>{t('Get ready to showcase your skills! Make sure you are available for all your matches, as missing a game might lead to disqualification. Ensure you read all rules carefully before participating.')}</p>
                </div>
                <div className='tournament-desc-rules-top'>
                    <h1>{t('How Does It work ?')}</h1>
                    <p>{t('Players will compete in a series of matches. Winners will advance to the next round, and the tournament will continue until a champion is crowned. Stay tuned for match updates and ensure you are prepared for each round!')}</p>
                </div>
            </div>
            <div className='tournament-top-player-container'>
                <h2>Tournament Creator</h2>
                <div className='tournament-top-player'>
                    <div className='tournament-top-player-avatar'>
                        <img src={avatars[0].img}/>
                        <div className='nameRank'>
                            <span>{profilData.username}</span>
                            <span>{t('Rank')} : {profilData.rank}</span>
                        </div>
                    </div>
                    <div className='tournament-top-player-stats'>
                        <div className='ownerWinRate'>
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
                            <p>WinRate</p>
                        </div>
                        <div className='ownerWinRate'>
                            <CircularProgressbar
                                value={30}
                                text={`${30}%`}
                                styles={buildStyles({
                                    pathColor: '#F62943',
                                    textColor: '#F62943',
                                    trailColor: '#A9A6A6',
                                    backgroundColor: '#11141B',
                                })}
                            />
                            <p>WinRate</p>

                            </div>
                            <div className='ownerWinRate'>

                            <CircularProgressbar
                                value={92}
                                text={`${92}%`}
                                styles={buildStyles({
                                    pathColor: '#F62943',
                                    textColor: '#F62943',
                                    trailColor: '#A9A6A6',
                                    backgroundColor: '#11141B',
                                })}
                            />
                            <p>WinRate</p>

                            </div>
                         
                    </div>
                    
                </div>
                             
            <div className='matchWillPlayed'>
                {Finishid  ?(
                    <>
                        <h1>Tournament Finished</h1>
                        <p>The tournament has ended. Congratulations to the winner!</p>
                        <h3>{winner}</h3>
                    </>

                ) : (

                    <>
                    <h2>Match will be played</h2>
                    <div className='PlayersVs'>
                    {matchToDisplay ? ( 
                        <>
                        <div className='firstPlayerVS'>
                            <div className='TournamentPlayers-firstPlayerImage'>
                                <img 
                                    src={matchToDisplay.player1.avatar ? `${BACKEND_URL}${matchToDisplay.player1.avatar}` : unknownAvatar} 
                                    alt={matchToDisplay.player1.avatar ? matchToDisplay.player1.username : 'Unknown Player'} 
                                    />
                            </div>
                            <div className='TournamentPlayers-firstPlayerName'>
                                <p>{matchToDisplay.player1.username || 'Unknown Player'}</p>
                            </div>
                        </div>
                        <div className='vsLogoVS'>
                            <p>VS</p>
                        </div>
                        <div className='secondPlayerVS'>
                            <div className='TournamentPlayers-secondPlayerName'>
                                <p>{matchToDisplay.player2.username || 'Unknown Player'}</p>
                            </div>
                            <div className='TournamentPlayers-secondPlayerImage'>
                                <img 
                                    src={matchToDisplay.player2.avatar ? `${BACKEND_URL}${matchToDisplay.player2.avatar}` : unknownAvatar} 
                                    alt={matchToDisplay.player2.avatar ? matchToDisplay.player2.username : 'Unknown Player'} 
                                    />
                            </div>
                        </div>
                    </>
                        ) : (
                            <p>No match available or loading...</p> // Fallback content
                        )}
                    </div>
                </>
                )}
            </div>
        </div>
    </div>
       
        <div className='JoinedTournomanentButoon'>
            {Finishid ? (
                <div className='leaveTournomantButton'>
                <MainButton type="submit" functionHandler={handleDeleteTournament} content="Finish"/>
                </div>
          
            ) : (
                <div className='TournamentTwoButton'> 

                <MainButton type="submit"  functionHandler={handleDeleteTournament} content="Cancel"/>
                <div className='disapledButton'
                    style={{
                        display: 'inline-block',
                        pointerEvents: TournamentData.tournament_participants && TournamentData.tournament_participants.length < 4 ? 'none' : 'auto',
                        opacity: TournamentData.tournament_participants && TournamentData.tournament_participants.length < 4 ? 0.5 : 1
                    }}
                >
                    <MainButton type="submit" functionHandler={handleStartTournament} content="Start"/>
                </div>
            </div>
            )}
        </div>
    </div>
  )
}

export default JoinedTournamentOffline