#ifndef ENFORCE_EXEC_SHARED_RECOVERY_TRANSITION_H
#define ENFORCE_EXEC_SHARED_RECOVERY_TRANSITION_H
#include "shared_recovery_abi.h"
#define RM_INLINE static __attribute__((always_inline)) inline
RM_INLINE int rt_zero(const struct rm_control *s)
{
	return !s->terminal && !s->incarnation && !s->guardian_task &&
	       !s->guardian_sequence && !s->guardian_phase && !s->admin_phase &&
	       !s->admin_task && !s->admin_generation && !s->admin_sequence &&
	       !s->admin_counter && !s->admin_death_task &&
	       !s->admin_death_generation && !s->admin_death_sequence &&
	       !s->admin_death_count && !s->recovery_phase &&
	       !s->recovery_epoch && !s->expected_old_generation &&
	       !s->expected_old_sequence && !s->candidate_task &&
	       !s->candidate_generation && !s->candidate_death_count &&
	       !s->capture_count && !s->candidate_death_task &&
	       !s->candidate_death_generation && !s->guardian_death_task &&
	       !s->guardian_death_sequence && !s->guardian_death_count &&
	       !s->reserved;
}
RM_INLINE int rt_rm_config_valid(const struct rm_config *c)
{
	return c && c->incarnation && c->bootstrap_nonce && c->abi == RM_ABI &&
	       c->scenario <= 1 && c->clone_flags == RM_CLONE_FLAGS;
}
RM_INLINE int rt_admin_death_zero(const struct rm_control *s)
{
	return !s->admin_death_task && !s->admin_death_generation &&
	       !s->admin_death_sequence && !s->admin_death_count;
}
RM_INLINE int rt_candidate_death_zero(const struct rm_control *s)
{
	return !s->candidate_death_task && !s->candidate_death_generation &&
	       !s->candidate_death_count;
}
RM_INLINE int rt_rm_cell_valid(const struct rm_control *s)
{
	if (!s)
		return 0;
	if (rt_zero(s))
		return 1;
	if (s->reserved || !s->incarnation || !s->guardian_task ||
	    !s->guardian_sequence || s->guardian_sequence > RM_LAST)
		return 0;
	if (s->guardian_phase == RM_G_ALIVE) {
		if (s->terminal || s->guardian_death_task ||
		    s->guardian_death_sequence || s->guardian_death_count)
			return 0;
	} else if (s->guardian_phase == RM_G_CLOSED) {
		if (s->terminal != RM_GUARDIAN_DEAD ||
		    s->guardian_death_task != s->guardian_task ||
		    s->guardian_death_sequence != s->guardian_sequence ||
		    s->guardian_death_count != 1)
			return 0;
	} else
		return 0;
	if (s->admin_phase == RM_A_EMPTY) {
		if (s->admin_task || s->admin_generation || s->admin_sequence ||
		    s->admin_counter || !rt_admin_death_zero(s))
			return 0;
	} else {
		if (!s->admin_task || !s->admin_generation ||
		    s->admin_generation > s->recovery_epoch ||
		    !s->admin_sequence || s->admin_sequence > RM_LAST ||
		    s->admin_counter > s->admin_sequence - 1)
			return 0;
		if (s->admin_phase == RM_A_ALIVE) {
			if (!rt_admin_death_zero(s))
				return 0;
		} else if (s->admin_phase == RM_A_CLOSED) {
			if (s->admin_death_task != s->admin_task ||
			    s->admin_death_generation != s->admin_generation ||
			    s->admin_death_sequence != s->admin_sequence ||
			    s->admin_death_count != 1)
				return 0;
		} else
			return 0;
	}
	if (s->recovery_phase == RM_IDLE) {
		if (s->recovery_epoch || s->expected_old_generation ||
		    s->expected_old_sequence || s->candidate_task ||
		    s->candidate_generation || s->capture_count ||
		    !rt_candidate_death_zero(s) || s->admin_phase != RM_A_EMPTY)
			return 0;
	} else {
		if (!s->recovery_epoch || s->recovery_epoch > RM_LAST ||
		    s->candidate_generation != s->recovery_epoch ||
		    s->expected_old_generation >= s->recovery_epoch ||
		    (!s->expected_old_generation) !=
			    (!s->expected_old_sequence) ||
		    s->expected_old_sequence > RM_LAST)
			return 0;
		switch (s->recovery_phase) {
		case RM_ARMED:
		case RM_CANCELLED:
			if (s->candidate_task || s->capture_count ||
			    !rt_candidate_death_zero(s))
				return 0;
			break;
		case RM_CAPTURED:
		case RM_READY:
			if (!s->candidate_task || s->capture_count != 1 ||
			    !rt_candidate_death_zero(s))
				return 0;
			break;
		case RM_DEAD:
			if (!s->candidate_task || s->capture_count != 1 ||
			    s->candidate_death_task != s->candidate_task ||
			    s->candidate_death_generation !=
				    s->candidate_generation ||
			    s->candidate_death_count != 1)
				return 0;
			break;
		case RM_COMMITTED:
			if (s->admin_phase == RM_A_EMPTY ||
			    s->candidate_task != s->admin_task ||
			    s->candidate_generation != s->admin_generation ||
			    s->capture_count != 1 ||
			    !rt_candidate_death_zero(s))
				return 0;
			break;
		default:
			return 0;
		}
		if (s->recovery_phase != RM_COMMITTED &&
		    (s->admin_phase == RM_A_ALIVE ||
		     s->admin_generation != s->expected_old_generation ||
		     s->admin_sequence != s->expected_old_sequence))
			return 0;
	}
	if (s->guardian_phase == RM_G_ALIVE && s->admin_phase == RM_A_ALIVE &&
	    s->guardian_task == s->admin_task)
		return 0;
	if ((s->recovery_phase == RM_CAPTURED ||
	     s->recovery_phase == RM_READY) &&
	    ((s->guardian_phase == RM_G_ALIVE &&
	      s->candidate_task == s->guardian_task) ||
	     (s->admin_phase == RM_A_ALIVE &&
	      s->candidate_task == s->admin_task)))
		return 0;
	return 1;
}
RM_INLINE void rt_receipt(struct rm_receipt *r, const struct rm_control *s,
			  __u64 inc, __u64 seq, __u64 task, __u32 op,
			  __u32 status)
{
	*r = (struct rm_receipt){ .incarnation = inc,
				  .attempted_sequence = seq,
				  .observed_physical_task = task,
				  .resulting_guardian_sequence =
					  s->guardian_sequence,
				  .admin_generation = s->admin_generation,
				  .admin_sequence = s->admin_sequence,
				  .recovery_epoch = s->recovery_epoch,
				  .candidate_task = s->candidate_task,
				  .operation = op,
				  .status = status,
				  .guardian_phase = s->guardian_phase,
				  .admin_phase = s->admin_phase,
				  .recovery_phase = s->recovery_phase,
				  .terminal = s->terminal };
}
RM_INLINE int rt_initialized_status(const struct rm_control *s)
{
	if (rt_zero(s))
		return RM_NOT_REGISTERED;
	if (s->guardian_phase != RM_G_ALIVE || s->terminal != RM_NORMAL)
		return RM_TERMINAL;
	return RM_ACCEPT;
}
RM_INLINE int rt_guardian_step(const struct rm_config *c, struct rm_control *s,
			       const struct rm_grequest *q, __u64 task)
{
	if (!rt_rm_config_valid(c))
		return RM_BAD_CONFIG;
	if (!task || q->operation < RM_REGISTER || q->operation > RM_COMMIT ||
	    q->reserved32 || q->reserved64 || !q->sequence ||
	    q->sequence == RM_MAX ||
	    (q->operation == RM_REGISTER &&
	     (q->sequence != 1 || q->expected_admin_generation ||
	      q->expected_admin_sequence || q->recovery_epoch)))
		return RM_BAD_REQUEST;
	if (q->incarnation != c->incarnation)
		return RM_WRONG_INCARNATION;
	if (q->nonce != c->bootstrap_nonce)
		return RM_WRONG_NONCE;
	if (!rt_rm_cell_valid(s) ||
	    (!rt_zero(s) && s->incarnation != c->incarnation))
		return RM_BAD_STATE;
	if (q->operation == RM_REGISTER) {
		if (!rt_zero(s))
			return RM_BAD_STATE;
		s->incarnation = c->incarnation;
		s->guardian_task = task;
		s->guardian_phase = RM_G_ALIVE;
		s->guardian_sequence = 1;
		return RM_ACCEPT;
	}
	int status = rt_initialized_status(s);
	if (status)
		return status;
	if (task != s->guardian_task)
		return RM_WRONG_TASK;
	if (s->guardian_sequence == RM_LAST)
		return RM_EXHAUSTED;
	if (q->sequence <= s->guardian_sequence)
		return RM_REPLAY;
	if (q->expected_admin_generation != s->admin_generation ||
	    q->expected_admin_sequence != s->admin_sequence)
		return RM_WRONG_OLD_TUPLE;
	if (q->recovery_epoch != s->recovery_epoch)
		return RM_WRONG_EPOCH;
	if (q->operation == RM_ARM) {
		if ((s->admin_phase != RM_A_EMPTY &&
		     s->admin_phase != RM_A_CLOSED) ||
		    (s->recovery_phase != RM_IDLE &&
		     s->recovery_phase != RM_CANCELLED &&
		     s->recovery_phase != RM_DEAD &&
		     s->recovery_phase != RM_COMMITTED))
			return RM_BAD_STATE;
		if (s->recovery_epoch == RM_LAST || q->sequence == RM_LAST)
			return RM_EXHAUSTED;
		s->guardian_sequence = q->sequence;
		s->recovery_epoch++;
		s->candidate_generation = s->recovery_epoch;
		s->expected_old_generation = s->admin_generation;
		s->expected_old_sequence = s->admin_sequence;
		s->recovery_phase = RM_ARMED;
		s->candidate_task = 0;
		s->capture_count = 0;
		s->candidate_death_task = 0;
		s->candidate_death_generation = 0;
		s->candidate_death_count = 0;
		return RM_ACCEPT;
	}
	if (q->operation == RM_CANCEL) {
		if (s->recovery_phase != RM_ARMED || s->capture_count)
			return RM_BAD_STATE;
		s->guardian_sequence = q->sequence;
		s->recovery_phase = RM_CANCELLED;
		return RM_ACCEPT;
	}
	if (s->recovery_phase != RM_READY || !rt_candidate_death_zero(s))
		return RM_BAD_STATE;
	s->guardian_sequence = q->sequence;
	s->admin_task = s->candidate_task;
	s->admin_generation = s->candidate_generation;
	s->admin_phase = RM_A_ALIVE;
	s->admin_sequence = 1;
	s->admin_counter = 0;
	s->admin_death_task = 0;
	s->admin_death_generation = 0;
	s->admin_death_sequence = 0;
	s->admin_death_count = 0;
	s->recovery_phase = RM_COMMITTED;
	return RM_ACCEPT;
}
RM_INLINE int rt_rm_guardian(const struct rm_config *c, struct rm_control *s,
			     const struct rm_grequest *q, __u64 task,
			     struct rm_receipt *r)
{
	if (!c || !s || !q || !r)
		return -1;
	int status = rt_guardian_step(c, s, q, task);
	rt_receipt(r, s, q->incarnation, q->sequence, task, q->operation,
		   (__u32)status);
	return status;
}
RM_INLINE int rt_admin_step(const struct rm_config *c, struct rm_control *s,
			    const struct rm_arequest *q, __u64 task)
{
	if (!rt_rm_config_valid(c))
		return RM_BAD_CONFIG;
	if (!task || q->operation < RM_A_READY || q->operation > RM_CHECK ||
	    q->reserved || !q->sequence || q->sequence == RM_MAX ||
	    (q->operation == RM_A_READY && q->sequence != 1) ||
	    (q->operation == RM_CHECK && q->recovery_epoch))
		return RM_BAD_REQUEST;
	if (q->incarnation != c->incarnation)
		return RM_WRONG_INCARNATION;
	if (!rt_rm_cell_valid(s) ||
	    (!rt_zero(s) && s->incarnation != c->incarnation))
		return RM_BAD_STATE;
	int status = rt_initialized_status(s);
	if (status)
		return status;
	if (q->operation == RM_A_READY) {
		if (task != s->candidate_task)
			return RM_WRONG_TASK;
		if (q->generation != s->candidate_generation)
			return RM_WRONG_GENERATION;
		if (q->recovery_epoch != s->recovery_epoch)
			return RM_WRONG_EPOCH;
		if (s->recovery_phase != RM_CAPTURED)
			return RM_BAD_STATE;
		s->recovery_phase = RM_READY;
		return RM_ACCEPT;
	}
	if (s->admin_phase != RM_A_ALIVE)
		return RM_NOT_ALIVE;
	if (task != s->admin_task)
		return RM_WRONG_TASK;
	if (q->generation != s->admin_generation)
		return RM_WRONG_GENERATION;
	if (s->admin_sequence == RM_LAST)
		return RM_EXHAUSTED;
	if (q->sequence <= s->admin_sequence)
		return RM_REPLAY;
	s->admin_sequence = q->sequence;
	s->admin_counter++;
	return RM_ACCEPT;
}
RM_INLINE int rt_rm_admin(const struct rm_config *c, struct rm_control *s,
			  const struct rm_arequest *q, __u64 task,
			  struct rm_receipt *r)
{
	if (!c || !s || !q || !r)
		return -1;
	int status = rt_admin_step(c, s, q, task);
	rt_receipt(r, s, q->incarnation, q->sequence, task, q->operation,
		   (__u32)status);
	return status;
}
RM_INLINE int rt_rm_alloc(const struct rm_config *c, struct rm_control *s,
			  __u64 current, __u64 child, __u64 flags, int prior)
{
	if (prior)
		return prior;
	if (!rt_rm_config_valid(c) || !rt_rm_cell_valid(s) || !s ||
	    s->incarnation != c->incarnation ||
	    s->guardian_phase != RM_G_ALIVE || s->terminal != RM_NORMAL ||
	    s->recovery_phase != RM_ARMED || current != s->guardian_task ||
	    !child || child == s->guardian_task ||
	    (flags != c->clone_flags && flags != RM_LSM_CLONE_FLAGS_NO_SIGNAL))
		return prior;
	s->candidate_task = child;
	s->capture_count = 1;
	s->recovery_phase = RM_CAPTURED;
	return c->scenario ? -1 : prior;
}
RM_INLINE int rt_rm_free(struct rm_control *s, __u64 dying)
{
	if (!s || !dying || !rt_rm_cell_valid(s) || rt_zero(s))
		return 0;
	if (s->guardian_phase == RM_G_ALIVE && s->guardian_task == dying) {
		s->guardian_phase = RM_G_CLOSED;
		s->guardian_death_task = s->guardian_task;
		s->guardian_death_sequence = s->guardian_sequence;
		s->guardian_death_count = 1;
		s->terminal = RM_GUARDIAN_DEAD;
	} else if (s->admin_phase == RM_A_ALIVE && s->admin_task == dying) {
		s->admin_phase = RM_A_CLOSED;
		s->admin_death_task = s->admin_task;
		s->admin_death_generation = s->admin_generation;
		s->admin_death_sequence = s->admin_sequence;
		s->admin_death_count = 1;
	} else if ((s->recovery_phase == RM_CAPTURED ||
		    s->recovery_phase == RM_READY) &&
		   s->candidate_task == dying) {
		s->recovery_phase = RM_DEAD;
		s->candidate_death_task = s->candidate_task;
		s->candidate_death_generation = s->candidate_generation;
		s->candidate_death_count = 1;
	}
	return 0;
}

#endif
