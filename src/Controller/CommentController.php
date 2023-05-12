<?php

namespace App\Controller;

use App\Entity\Comment;
use App\Entity\Vote;
use App\Repository\VoteRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

class CommentController extends AbstractController
{
    #[Route('/comment/rating/{id}/{score}', name: 'comment_rating')]
    #[IsGranted('IS_AUTHENTICATED_REMEMBERED')]
    public function rate(Request $request ,Comment $comment, int $score, EntityManagerInterface $em, VoteRepository $voteRepository) {
        $currentUser = $this->getUser();

        // je verifie que le current user n'est pas le propriétaire de la question
        if($currentUser !== $comment->getAuthor()) {

            // on verifie que le current user a deja voter
            $vote = $voteRepository->findOneBy([
                'author' => $currentUser,
                'comment' => $comment
            ]);

            if($vote) {
                // s'il avait aimer le commentaire ET qu'il reclique sur le like (score = 1) c est pour enleve son vote
                // OU
                // s'il n'avait pas aimer le commentaire ET qu'il reclique sur le dislike (score = -1) c'est pour enlever son vote
                if(($vote->getIsLiked() && $score > 0 ) || (!$vote->getIsLiked() && $score < 0)) {
                    // on supprime le vote
                    $em->remove($vote);
                    $comment->setRating($comment->getRating() + ($score > 0 ? -1 : 1));
                } else {
                    $vote->setIsLiked(!$vote->getIsLiked());
                    $comment->setRating($comment->getRating() + ($score > 0 ? 2 : -2));
                }
            } else {
                //on le laisse vote
                $newVote = new Vote();
                $newVote->setAuthor($currentUser)
                        ->setComment($comment)
                        ->setIsLiked($score > 0 ? true : false);
                $em->persist($newVote);
                $comment->setRating($comment->getRating() + $score);
            }

            $em->flush();

        }

        $referer = $request->server->get('HTTP_REFERER');
        return $referer ? $this->redirect($referer) : $this->redirectToRoute('home');
    }
}

